<?php
/**
 * TaintScope PHP AST dumper.
 *
 * Reads a PHP source file (path passed as argv[1]) and prints a JSON
 * representation of its AST using nikic/PHP-Parser. The JSON shape is
 * a list of normalized node objects consumed by the Python engine:
 *
 *   {
 *     "nodeType": "Stmt_Function",
 *     "name": "foo",
 *     "params": [...],
 *     "stmts": [...],
 *     ...
 *   }
 *
 * Usage: php dump_ast.php <file.php>
 */

require __DIR__ . '/vendor/autoload.php';

use PhpParser\ParserFactory;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor\NameResolver;

if ($argc < 2) {
    fwrite(STDERR, "Usage: php dump_ast.php <file.php>\n");
    exit(2);
}

$path = $argv[1];
if (!is_file($path)) {
    fwrite(STDERR, "File not found: $path\n");
    exit(2);
}

$code = file_get_contents($path);

$parser = (new ParserFactory)->create(ParserFactory::PREFER_PHP7);
try {
    $ast = $parser->parse($code);
} catch (\PhpParser\Error $e) {
    fwrite(STDERR, "Parse error: " . $e->getMessage() . "\n");
    exit(1);
}

// Resolve names so that fully-qualified names appear in the AST.
$traverser = new NodeTraverser();
$traverser->addVisitor(new NameResolver);
$ast = $traverser->traverse($ast);

// PHP-Parser nodes implement JsonSerializable, so json_encode produces a
// faithful, lossless tree. JSON_UNESCAPED_SLASHES keeps paths readable and
// JSON_THROW_ON_ERROR surfaces any encoding issues.
echo json_encode($ast, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
