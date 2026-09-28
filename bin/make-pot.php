<?php
/**
 * Builds languages/mighty-shield.pot from the plugin's PHP and JavaScript.
 *
 * Stands in for `wp i18n make-pot`, which needs WP-CLI and a working PHP on
 * the PATH -- neither of which every contributor has. Development tooling:
 * this file does not ship in the release ZIP (see .distignore).
 *
 * PHP is tokenised rather than pattern-matched, so a gettext call that spans
 * lines, or a string that contains a bracket, is read correctly. JavaScript is
 * walked with a small string-literal parser for the same reason. Only literal
 * arguments are extracted; a variable passed to __() is not translatable
 * anyway, and is reported at the end rather than guessed at.
 *
 * A `translators:` comment on the line before a call is carried into the
 * template, as the WordPress tooling does.
 *
 * Usage:
 *     php bin/make-pot.php [plugin-root] [--allow-removals]
 *
 * The template that exists is compared with the one about to be written. If
 * strings would disappear, nothing is written and they are listed, because a
 * string that leaves the template silently is a string no translator will be
 * offered again. Pass --allow-removals once you have checked the list.
 */

$argv_ = array_slice( $argv, 1 );
$allow = in_array( '--allow-removals', $argv_, true );
$argv_ = array_values( array_diff( $argv_, [ '--allow-removals' ] ) );
$root  = rtrim( str_replace( '\\', '/', realpath( $argv_[0] ?? dirname( __DIR__ ) ) ), '/' );

$domain = 'mighty-shield';
$out    = "$root/languages/$domain.pot";

// Directories that hold nothing a translator should see.
$skip = [ '.git', '.github', 'bin', 'vendor', 'node_modules', 'languages', 'tests', 'updates' ];

// name => [ singular index, plural index or null, context index or null, domain index ]
$FUNCS = [
    '__'             => [ 0, null, null, 1 ],
    '_e'             => [ 0, null, null, 1 ],
    'esc_html__'     => [ 0, null, null, 1 ],
    'esc_html_e'     => [ 0, null, null, 1 ],
    'esc_attr__'     => [ 0, null, null, 1 ],
    'esc_attr_e'     => [ 0, null, null, 1 ],
    '_x'             => [ 0, null, 1, 2 ],
    '_ex'            => [ 0, null, 1, 2 ],
    'esc_html_x'     => [ 0, null, 1, 2 ],
    'esc_attr_x'     => [ 0, null, 1, 2 ],
    '_n'             => [ 0, 1, null, 3 ],
    '_nx'            => [ 0, 1, 3, 4 ],
    '_n_noop'        => [ 0, 1, null, 2 ],
    '_nx_noop'       => [ 0, 1, 2, 3 ],
];

$strings = [];   // key => [ id, plural, ctx, refs[], comments[] ]
$dynamic = [];

/**
 * Record one extracted string.
 */
function record( array &$strings, $msgid, $plural, $context, $ref, $comment ) {
    $key = ( $context ?? '' ) . "\4" . $msgid . "\5" . ( $plural ?? '' );
    if ( ! isset( $strings[ $key ] ) ) {
        $strings[ $key ] = [ 'id' => $msgid, 'plural' => $plural, 'ctx' => $context, 'refs' => [], 'comments' => [] ];
    }
    $strings[ $key ]['refs'][] = $ref;
    if ( $comment !== null && $comment !== '' ) {
        $strings[ $key ]['comments'][] = $comment;
    }
}

/**
 * Normalise a translators comment to the one line the template carries.
 */
function translators_comment( $raw ) {
    $text = preg_replace( '#^\s*(/\*+|//|\*+/|\*)\s?#m', '', $raw );
    $text = preg_replace( '#\s*\*+/\s*$#', '', $text );
    $text = trim( preg_replace( '/\s+/', ' ', $text ) );
    return preg_match( '/\btranslators:/i', $text ) ? $text : null;
}

/* -------------------------------------------------------------------------
 * PHP
 * ---------------------------------------------------------------------- */

function extract_php( $path, $rel, array &$strings, array &$dynamic, array $FUNCS, $domain ) {

    $tokens = token_get_all( file_get_contents( $path ) );
    $n      = count( $tokens );

    // The most recent comment, and the line it ends on, so a translators note
    // on the line before a call can be attached to it.
    $last_comment = null;
    $last_comment_end = -10;

    for ( $i = 0; $i < $n; $i++ ) {

        $t = $tokens[ $i ];

        if ( is_array( $t ) && ( $t[0] === T_COMMENT || $t[0] === T_DOC_COMMENT ) ) {
            $last_comment     = translators_comment( $t[1] );
            $last_comment_end = $t[2] + substr_count( $t[1], "\n" );
            continue;
        }

        if ( ! is_array( $t ) || $t[0] !== T_STRING || ! isset( $FUNCS[ $t[1] ] ) ) { continue; }

        // Skip method calls and declarations: ->__(), ::__(), function __()
        $prev = $i > 0 ? $tokens[ $i - 1 ] : null;
        if ( is_array( $prev ) && in_array( $prev[0], [ T_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION ], true ) ) { continue; }

        // Next non-whitespace must be '('
        $j = $i + 1;
        while ( $j < $n && is_array( $tokens[ $j ] ) && $tokens[ $j ][0] === T_WHITESPACE ) { $j++; }
        if ( $tokens[ $j ] !== '(' ) { continue; }

        // Collect top-level comma-separated arguments.
        $depth = 0; $args = []; $cur = []; $k = $j;
        for ( ; $k < $n; $k++ ) {
            $tk = $tokens[ $k ];
            if ( $tk === '(' ) { $depth++; if ( $depth === 1 ) { continue; } }
            if ( $tk === ')' ) { $depth--; if ( $depth === 0 ) { $args[] = $cur; break; } }
            if ( $tk === ',' && $depth === 1 ) { $args[] = $cur; $cur = []; continue; }
            if ( is_array( $tk ) && in_array( $tk[0], [ T_WHITESPACE, T_COMMENT, T_DOC_COMMENT ], true ) ) {
                // A translators note may sit inside the call too, right
                // before the string.
                if ( $tk[0] !== T_WHITESPACE && empty( $cur ) ) {
                    $inner = translators_comment( $tk[1] );
                    if ( $inner !== null ) { $last_comment = $inner; $last_comment_end = $tk[2] + substr_count( $tk[1], "\n" ); }
                }
                continue;
            }
            $cur[] = $tk;
        }

        $literal = function ( $arg ) {
            // A single quoted string, or several concatenated with '.'
            $parts = [];
            foreach ( $arg as $tk ) {
                if ( $tk === '.' ) { continue; }
                if ( ! is_array( $tk ) || $tk[0] !== T_CONSTANT_ENCAPSED_STRING ) { return null; }
                $raw = $tk[1];
                $q   = $raw[0];
                $s   = substr( $raw, 1, -1 );
                $parts[] = $q === "'"
                    ? str_replace( [ "\\'", '\\\\' ], [ "'", '\\' ], $s )
                    : stripcslashes( $s );
            }
            return $parts ? implode( '', $parts ) : null;
        };

        [ $si, $pi, $ci, $di ] = $FUNCS[ $t[1] ];

        $dom = isset( $args[ $di ] ) ? $literal( $args[ $di ] ) : null;
        if ( $dom !== $domain ) { continue; }

        $msgid = isset( $args[ $si ] ) ? $literal( $args[ $si ] ) : null;
        if ( $msgid === null ) {
            $dynamic[] = "$rel:{$t[2]}  {$t[1]}() with a non-literal string";
            continue;
        }

        $plural  = $pi !== null && isset( $args[ $pi ] ) ? $literal( $args[ $pi ] ) : null;
        $context = $ci !== null && isset( $args[ $ci ] ) ? $literal( $args[ $ci ] ) : null;

        // The note counts if it ended on the line before the call, or the
        // line before the sprintf() the call sits inside.
        $comment = ( $t[2] - $last_comment_end ) <= 2 ? $last_comment : null;

        record( $strings, $msgid, $plural, $context, "$rel:{$t[2]}", $comment );
    }
}

/* -------------------------------------------------------------------------
 * JavaScript
 * ---------------------------------------------------------------------- */

/**
 * Split the arguments of a call starting just after its '('.
 *
 * Returns [ args, end ] where each arg is [ 'literal' => string|null ]. An
 * argument is a literal when it is one string, or several joined with '+'.
 */
function js_args( $src, $pos ) {

    $n = strlen( $src );
    $args = []; $parts = []; $other = false; $depth = 0;

    $flush = function () use ( &$args, &$parts, &$other ) {
        $args[]  = [ 'literal' => ( $parts && ! $other ) ? implode( '', $parts ) : null ];
        $parts   = [];
        $other   = false;
    };

    while ( $pos < $n ) {

        $c = $src[ $pos ];

        if ( $c === "'" || $c === '"' ) {
            $q = $c; $pos++; $s = '';
            while ( $pos < $n && $src[ $pos ] !== $q ) {
                if ( $src[ $pos ] === '\\' && $pos + 1 < $n ) {
                    $e = $src[ $pos + 1 ];
                    $s .= [ 'n' => "\n", 't' => "\t", 'r' => "\r" ][ $e ] ?? $e;
                    $pos += 2;
                    continue;
                }
                $s .= $src[ $pos++ ];
            }
            $pos++;
            $parts[] = $s;
            continue;
        }

        if ( $c === '/' && $pos + 1 < $n && $src[ $pos + 1 ] === '/' ) {
            while ( $pos < $n && $src[ $pos ] !== "\n" ) { $pos++; }
            continue;
        }
        if ( $c === '/' && $pos + 1 < $n && $src[ $pos + 1 ] === '*' ) {
            $end = strpos( $src, '*/', $pos + 2 );
            $pos = $end === false ? $n : $end + 2;
            continue;
        }

        if ( $c === '(' || $c === '[' || $c === '{' ) { $depth++; $other = true; $pos++; continue; }
        if ( $c === ')' || $c === ']' || $c === '}' ) {
            if ( $depth === 0 ) { $flush(); return [ $args, $pos + 1 ]; }
            $depth--; $pos++; continue;
        }
        if ( $c === ',' && $depth === 0 ) { $flush(); $pos++; continue; }
        if ( strpos( " \t\r\n", $c ) !== false || $c === '+' ) { $pos++; continue; }

        $other = true;
        $pos++;
    }

    $flush();
    return [ $args, $pos ];
}

function extract_js( $path, $rel, array &$strings, array &$dynamic, array $FUNCS, $domain ) {

    $src = file_get_contents( $path );

    if ( ! preg_match_all( '/(?<![\w$.])(__|_x|_n|_nx)\s*\(/', $src, $m, PREG_OFFSET_CAPTURE ) ) { return; }

    foreach ( $m[1] as $idx => [ $name, $offset ] ) {

        $open = $m[0][ $idx ][1] + strlen( $m[0][ $idx ][0] );
        [ $args ] = js_args( $src, $open );
        $line = substr_count( $src, "\n", 0, $offset ) + 1;

        [ $si, $pi, $ci, $di ] = $FUNCS[ $name ];

        if ( ( $args[ $di ]['literal'] ?? null ) !== $domain ) { continue; }

        $msgid = $args[ $si ]['literal'] ?? null;
        if ( $msgid === null ) {
            $dynamic[] = "$rel:$line  $name() with a non-literal string";
            continue;
        }

        $plural  = $pi !== null ? ( $args[ $pi ]['literal'] ?? null ) : null;
        $context = $ci !== null ? ( $args[ $ci ]['literal'] ?? null ) : null;

        // A translators note on the line (or two) before.
        $comment = null;
        $lines   = explode( "\n", substr( $src, 0, $offset ) );
        $before  = array_slice( $lines, -3, 2 );
        foreach ( array_reverse( $before ) as $l ) {
            $c = translators_comment( trim( $l ) );
            if ( $c !== null ) { $comment = $c; break; }
        }

        record( $strings, $msgid, $plural, $context, "$rel:$line", $comment );
    }
}

/* -------------------------------------------------------------------------
 * Walk
 * ---------------------------------------------------------------------- */

$files = new RecursiveIteratorIterator(
    new RecursiveCallbackFilterIterator(
        new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ),
        function ( $file ) use ( $skip ) {
            return ! ( $file->isDir() && in_array( $file->getFilename(), $skip, true ) );
        }
    )
);

$counts = [ 'php' => 0, 'js' => 0 ];

foreach ( $files as $file ) {

    $ext = $file->getExtension();
    if ( $ext !== 'php' && $ext !== 'js' ) { continue; }

    $path = str_replace( '\\', '/', $file->getPathname() );
    $rel  = substr( $path, strlen( $root ) + 1 );

    $counts[ $ext ]++;

    if ( $ext === 'php' ) { extract_php( $path, $rel, $strings, $dynamic, $FUNCS, $domain ); }
    else                  { extract_js( $path, $rel, $strings, $dynamic, $FUNCS, $domain ); }
}

ksort( $strings );

/* -------------------------------------------------------------------------
 * Compare with what exists, then write
 * ---------------------------------------------------------------------- */

$previous = [];
if ( is_file( $out ) ) {
    foreach ( explode( "\n\n", file_get_contents( $out ) ) as $block ) {
        if ( preg_match( '/^msgid "(.*)"$/m', $block, $mm ) && $mm[1] !== '' ) {
            $previous[ stripcslashes( $mm[1] ) ] = true;
        }
    }
}
$now = [];
foreach ( $strings as $s ) { $now[ $s['id'] ] = true; }
$removed = array_keys( array_diff_key( $previous, $now ) );

$version = '0.0.0';
if ( preg_match( '/^\s*\*\s*Version:\s*(\S+)/m', (string) file_get_contents( "$root/mighty-shield.php" ), $vm ) ) { $version = $vm[1]; }

$esc = fn( $s ) => '"' . str_replace( [ '\\', '"', "\n", "\t" ], [ '\\\\', '\\"', '\\n', '\\t' ], $s ) . '"';

$pot = "# Copyright (C) " . gmdate( 'Y' ) . " Built Mighty\n"
     . "# This file is distributed under the GPL-2.0-or-later license.\n"
     . "msgid \"\"\nmsgstr \"\"\n"
     . "\"Project-Id-Version: MightyShield $version\\n\"\n"
     . "\"Report-Msgid-Bugs-To: https://builtmighty.com\\n\"\n"
     . "\"POT-Creation-Date: " . gmdate( 'Y-m-d H:i' ) . "+0000\\n\"\n"
     . "\"MIME-Version: 1.0\\n\"\n"
     . "\"Content-Type: text/plain; charset=UTF-8\\n\"\n"
     . "\"Content-Transfer-Encoding: 8bit\\n\"\n"
     . "\"PO-Revision-Date: YEAR-MO-DA HO:MI+ZONE\\n\"\n"
     . "\"Last-Translator: FULL NAME <EMAIL@ADDRESS>\\n\"\n"
     . "\"Language-Team: LANGUAGE <LL@li.org>\\n\"\n"
     . "\"Plural-Forms: nplurals=2; plural=(n != 1);\\n\"\n"
     . "\"X-Generator: MightyShield bin/make-pot.php\\n\"\n"
     . "\"X-Domain: $domain\\n\"\n";

foreach ( $strings as $s ) {
    $pot .= "\n";
    foreach ( array_unique( $s['comments'] ) as $c ) {
        $pot .= "#. $c\n";
    }
    foreach ( array_chunk( array_unique( $s['refs'] ), 4 ) as $chunk ) {
        $pot .= '#: ' . implode( ' ', $chunk ) . "\n";
    }
    if ( $s['ctx'] !== null ) { $pot .= 'msgctxt ' . $esc( $s['ctx'] ) . "\n"; }
    $pot .= 'msgid ' . $esc( $s['id'] ) . "\n";
    if ( $s['plural'] !== null ) {
        $pot .= 'msgid_plural ' . $esc( $s['plural'] ) . "\n";
        $pot .= "msgstr[0] \"\"\nmsgstr[1] \"\"\n";
    } else {
        $pot .= "msgstr \"\"\n";
    }
}

printf( "%d PHP and %d JS files scanned; %d unique strings\n", $counts['php'], $counts['js'], count( $strings ) );

if ( $dynamic ) {
    echo "\nNot extracted (non-literal argument):\n";
    foreach ( array_unique( $dynamic ) as $d ) { echo "  $d\n"; }
}

if ( $removed && ! $allow ) {
    echo "\nNOT WRITTEN. These strings are in the current template and would be dropped:\n";
    foreach ( $removed as $r ) { echo "  " . $esc( $r ) . "\n"; }
    echo "\nIf that is intended, run again with --allow-removals.\n";
    exit( 1 );
}

@mkdir( dirname( $out ), 0755, true );
file_put_contents( $out, $pot );

echo "-> $out\n";
if ( $removed ) { printf( "%d string(s) removed from the template.\n", count( $removed ) ); }
exit( 0 );
