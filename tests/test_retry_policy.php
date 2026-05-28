<?php
/**
 * ============================================================
 *  TEST RETRY POLICY — SDK ACH PSE ePayco
 * ============================================================
 *  Script de pruebas para tomar evidencias de la implementación
 *  del patrón Retry Policy en RequestServices.
 *
 *  Ejecutar: php test_retry_policy.php
 * ============================================================
 */

require_once __DIR__ . '/../vendor/autoload.php';

use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use PSEIntegration\Services\RequestServices;

// ─────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────

/**
 * Access the private static method executeWithRetry via Reflection
 */
function getExecuteWithRetry(): ReflectionMethod
{
    $method = new ReflectionMethod(RequestServices::class, 'executeWithRetry');
    $method->setAccessible(true);
    return $method;
}

/**
 * Print a formatted test header
 */
function printHeader(string $testName, int $testNumber): void
{
    echo PHP_EOL;
    echo "┌─────────────────────────────────────────────────────────────┐" . PHP_EOL;
    echo "│  TEST #{$testNumber}: {$testName}" . PHP_EOL;
    echo "└─────────────────────────────────────────────────────────────┘" . PHP_EOL;
}

/**
 * Print a result line
 */
function printResult(bool $passed, string $message): void
{
    $icon = $passed ? '✅' : '❌';
    echo "  {$icon} {$message}" . PHP_EOL;
}

/**
 * Print attempt log
 */
function printAttempt(int $attempt, string $result): void
{
    echo "     ↳ Intento #{$attempt}: {$result}" . PHP_EOL;
}

// ─────────────────────────────────────────────
//  Tests
// ─────────────────────────────────────────────

$executeWithRetry = getExecuteWithRetry();
$totalTests = 0;
$passedTests = 0;

echo PHP_EOL;
echo "╔═════════════════════════════════════════════════════════════════╗" . PHP_EOL;
echo "║     RETRY POLICY TEST SUITE — SDK ACH PSE ePayco              ║" . PHP_EOL;
echo "║     Fecha: " . date('Y-m-d H:i:s') . "                              ║" . PHP_EOL;
echo "╚═════════════════════════════════════════════════════════════════╝" . PHP_EOL;


// ── TEST 1: Éxito en el primer intento (sin retry necesario) ──
$testNum = 1;
$totalTests++;
printHeader("Éxito en el primer intento (sin retry)", $testNum);

$attempts = 0;
try {
    $result = $executeWithRetry->invoke(null,
        function () use (&$attempts) {
            $attempts++;
            printAttempt($attempts, "Respuesta 200 OK");
            return new Response(200, [], '{"status":"ok"}');
        },
        5,     // retryCount
        100    // retryDelay (ms)
    );

    $passed = ($result->getStatusCode() === 200 && $attempts === 1);
    printResult($passed, "Status: {$result->getStatusCode()} | Intentos realizados: {$attempts} (esperado: 1)");
    if ($passed) $passedTests++;
} catch (\Throwable $e) {
    printResult(false, "Excepción inesperada: " . $e->getMessage());
}


// ── TEST 2: ConnectException → se reintenta y luego éxito ──
$testNum = 2;
$totalTests++;
printHeader("ConnectException → Reintentos → Éxito", $testNum);

$attempts = 0;
try {
    $result = $executeWithRetry->invoke(null,
        function () use (&$attempts) {
            $attempts++;
            if ($attempts <= 3) {
                printAttempt($attempts, "ConnectException (timeout de red)");
                throw new ConnectException(
                    "Connection timed out",
                    new Request('POST', '/api/test')
                );
            }
            printAttempt($attempts, "Respuesta 200 OK ✓");
            return new Response(200, [], '{"status":"recovered"}');
        },
        5,     // retryCount
        100    // retryDelay (ms)
    );

    $passed = ($result->getStatusCode() === 200 && $attempts === 4);
    printResult($passed, "Recuperado después de 3 fallos | Intentos: {$attempts} (esperado: 4)");
    if ($passed) $passedTests++;
} catch (\Throwable $e) {
    printResult(false, "Excepción inesperada: " . $e->getMessage());
}


// ── TEST 3: Error 503 → se reintenta y luego éxito ──
$testNum = 3;
$totalTests++;
printHeader("Error 503 (Server Unavailable) → Reintentos → Éxito", $testNum);

$attempts = 0;
try {
    $result = $executeWithRetry->invoke(null,
        function () use (&$attempts) {
            $attempts++;
            if ($attempts <= 2) {
                printAttempt($attempts, "RequestException 503 Service Unavailable");
                $response = new Response(503, [], 'Service Unavailable');
                throw new RequestException(
                    "Server Error",
                    new Request('POST', '/api/test'),
                    $response
                );
            }
            printAttempt($attempts, "Respuesta 200 OK ✓");
            return new Response(200, [], '{"status":"server_recovered"}');
        },
        5,     // retryCount
        100    // retryDelay (ms)
    );

    $passed = ($result->getStatusCode() === 200 && $attempts === 3);
    printResult($passed, "Recuperado después de 2 errores 503 | Intentos: {$attempts} (esperado: 3)");
    if ($passed) $passedTests++;
} catch (\Throwable $e) {
    printResult(false, "Excepción inesperada: " . $e->getMessage());
}


// ── TEST 4: Error 400 → NO se reintenta (error de cliente) ──
$testNum = 4;
$totalTests++;
printHeader("Error 400 (Bad Request) → NO debe reintentar", $testNum);

$attempts = 0;
try {
    $result = $executeWithRetry->invoke(null,
        function () use (&$attempts) {
            $attempts++;
            printAttempt($attempts, "RequestException 400 Bad Request");
            $response = new Response(400, [], '{"error":"invalid_request"}');
            throw new RequestException(
                "Bad Request",
                new Request('POST', '/api/test'),
                $response
            );
        },
        5,     // retryCount
        100    // retryDelay (ms)
    );

    printResult(false, "Debió lanzar excepción pero no lo hizo");
} catch (RequestException $e) {
    $passed = ($attempts === 1 && $e->getResponse()->getStatusCode() === 400);
    printResult($passed, "Excepción lanzada inmediatamente sin reintentar | Intentos: {$attempts} (esperado: 1)");
    printResult($passed, "Status code: {$e->getResponse()->getStatusCode()} | Mensaje: {$e->getMessage()}");
    if ($passed) $passedTests++;
} catch (\Throwable $e) {
    printResult(false, "Excepción incorrecta: " . get_class($e));
}


// ── TEST 5: Error 404 → NO se reintenta ──
$testNum = 5;
$totalTests++;
printHeader("Error 404 (Not Found) → NO debe reintentar", $testNum);

$attempts = 0;
try {
    $result = $executeWithRetry->invoke(null,
        function () use (&$attempts) {
            $attempts++;
            printAttempt($attempts, "RequestException 404 Not Found");
            $response = new Response(404, [], 'Not Found');
            throw new RequestException(
                "Not Found",
                new Request('POST', '/api/test'),
                $response
            );
        },
        5,     // retryCount
        100    // retryDelay (ms)
    );

    printResult(false, "Debió lanzar excepción pero no lo hizo");
} catch (RequestException $e) {
    $passed = ($attempts === 1 && $e->getResponse()->getStatusCode() === 404);
    printResult($passed, "Excepción lanzada inmediatamente sin reintentar | Intentos: {$attempts} (esperado: 1)");
    if ($passed) $passedTests++;
} catch (\Throwable $e) {
    printResult(false, "Excepción incorrecta: " . get_class($e));
}


// ── TEST 6: Error 422 → NO se reintenta ──
$testNum = 6;
$totalTests++;
printHeader("Error 422 (Unprocessable Entity) → NO debe reintentar", $testNum);

$attempts = 0;
try {
    $result = $executeWithRetry->invoke(null,
        function () use (&$attempts) {
            $attempts++;
            printAttempt($attempts, "RequestException 422 Unprocessable Entity");
            $response = new Response(422, [], '{"error":"validation_failed"}');
            throw new RequestException(
                "Unprocessable Entity",
                new Request('POST', '/api/test'),
                $response
            );
        },
        5,     // retryCount
        100    // retryDelay (ms)
    );

    printResult(false, "Debió lanzar excepción pero no lo hizo");
} catch (RequestException $e) {
    $passed = ($attempts === 1);
    printResult($passed, "Excepción lanzada inmediatamente sin reintentar | Intentos: {$attempts} (esperado: 1)");
    if ($passed) $passedTests++;
} catch (\Throwable $e) {
    printResult(false, "Excepción incorrecta: " . get_class($e));
}


// ── TEST 7: Agota todos los reintentos → lanza excepción final ──
$testNum = 7;
$totalTests++;
printHeader("Agotar todos los reintentos (retryCount=3) → Excepción final", $testNum);

$attempts = 0;
$retryCount = 3;
try {
    $result = $executeWithRetry->invoke(null,
        function () use (&$attempts) {
            $attempts++;
            printAttempt($attempts, "ConnectException (fallo permanente)");
            throw new ConnectException(
                "Connection refused (intento #{$attempts})",
                new Request('POST', '/api/test')
            );
        },
        $retryCount,
        100    // retryDelay (ms)
    );

    printResult(false, "Debió lanzar excepción pero no lo hizo");
} catch (ConnectException $e) {
    $expectedAttempts = $retryCount + 1; // 1 original + 3 retries = 4
    $passed = ($attempts === $expectedAttempts);
    printResult($passed, "Excepción final después de agotar reintentos | Intentos: {$attempts} (esperado: {$expectedAttempts})");
    printResult($passed, "Último mensaje: {$e->getMessage()}");
    if ($passed) $passedTests++;
} catch (\Throwable $e) {
    printResult(false, "Excepción incorrecta: " . get_class($e));
}


// ── TEST 8: retryCount=0 → sin reintentos ──
$testNum = 8;
$totalTests++;
printHeader("retryCount=0 → Solo 1 intento, sin reintentos", $testNum);

$attempts = 0;
try {
    $result = $executeWithRetry->invoke(null,
        function () use (&$attempts) {
            $attempts++;
            printAttempt($attempts, "ConnectException");
            throw new ConnectException(
                "Connection refused",
                new Request('POST', '/api/test')
            );
        },
        0,     // retryCount = 0 (desactivado)
        100    // retryDelay (ms)
    );

    printResult(false, "Debió lanzar excepción pero no lo hizo");
} catch (ConnectException $e) {
    $passed = ($attempts === 1);
    printResult($passed, "Sin reintentos, falla inmediatamente | Intentos: {$attempts} (esperado: 1)");
    if ($passed) $passedTests++;
} catch (\Throwable $e) {
    printResult(false, "Excepción incorrecta: " . get_class($e));
}


// ── TEST 9: Verificar que el delay realmente se aplica ──
$testNum = 9;
$totalTests++;
printHeader("Verificar delay entre reintentos (retryDelay=200ms, retryCount=3)", $testNum);

$attempts = 0;
$retryCount = 3;
$retryDelay = 200; // ms
$startTime = microtime(true);
$GLOBALS['test9_start'] = $startTime;

try {
    $result = $executeWithRetry->invoke(null,
        function () use (&$attempts, $retryCount) {
            $attempts++;
            $elapsed = round((microtime(true) - $GLOBALS['test9_start']) * 1000);
            printAttempt($attempts, "ConnectException (t={$elapsed}ms)");
            throw new ConnectException(
                "Timeout",
                new Request('POST', '/api/test')
            );
        },
        $retryCount,
        $retryDelay
    );
} catch (ConnectException $e) {
    $totalElapsed = round((microtime(true) - $startTime) * 1000);
    $expectedMinDelay = $retryCount * $retryDelay; // 3 * 200 = 600ms
    $passed = ($totalElapsed >= $expectedMinDelay * 0.8); // tolerancia del 20%
    printResult($passed, "Tiempo total: {$totalElapsed}ms (esperado mínimo: {$expectedMinDelay}ms)");
    printResult($passed, "Delay verificado: ~{$retryDelay}ms entre cada reintento");
    if ($passed) $passedTests++;
}


// ── TEST 10: Error 500 mixto con ConnectException → éxito final ──
$testNum = 10;
$totalTests++;
printHeader("Errores mixtos (ConnectException + 500) → Éxito final", $testNum);

$attempts = 0;
try {
    $result = $executeWithRetry->invoke(null,
        function () use (&$attempts) {
            $attempts++;
            if ($attempts === 1) {
                printAttempt($attempts, "ConnectException (DNS resolution failed)");
                throw new ConnectException(
                    "DNS resolution failed",
                    new Request('POST', '/api/test')
                );
            }
            if ($attempts === 2) {
                printAttempt($attempts, "RequestException 500 Internal Server Error");
                $response = new Response(500, [], 'Internal Server Error');
                throw new RequestException(
                    "Server Error",
                    new Request('POST', '/api/test'),
                    $response
                );
            }
            if ($attempts === 3) {
                printAttempt($attempts, "RequestException 502 Bad Gateway");
                $response = new Response(502, [], 'Bad Gateway');
                throw new RequestException(
                    "Bad Gateway",
                    new Request('POST', '/api/test'),
                    $response
                );
            }
            printAttempt($attempts, "Respuesta 200 OK ✓");
            return new Response(200, [], '{"status":"finally_ok"}');
        },
        5,     // retryCount
        100    // retryDelay (ms)
    );

    $passed = ($result->getStatusCode() === 200 && $attempts === 4);
    printResult($passed, "Recuperado después de 3 errores mixtos | Intentos: {$attempts} (esperado: 4)");
    if ($passed) $passedTests++;
} catch (\Throwable $e) {
    printResult(false, "Excepción inesperada: " . $e->getMessage());
}


// ── TEST 11: Verificar defaults de PSEIntegration ──
$testNum = 11;
$totalTests++;
printHeader("Verificar defaults del constructor PSEIntegration", $testNum);

$reflection = new ReflectionMethod(\PSEIntegration\PSEIntegration::class, '__construct');
$params = $reflection->getParameters();

$retryCountParam = null;
$retryDelayParam = null;

foreach ($params as $param) {
    if ($param->getName() === 'retryCount') $retryCountParam = $param;
    if ($param->getName() === 'retryDelay') $retryDelayParam = $param;
}

$hasRetryCount = $retryCountParam !== null && $retryCountParam->isDefaultValueAvailable();
$hasRetryDelay = $retryDelayParam !== null && $retryDelayParam->isDefaultValueAvailable();

if ($hasRetryCount && $hasRetryDelay) {
    $defaultCount = $retryCountParam->getDefaultValue();
    $defaultDelay = $retryDelayParam->getDefaultValue();

    $countCorrect = ($defaultCount === 5);
    $delayCorrect = ($defaultDelay === 1000);

    printResult($countCorrect, "retryCount default = {$defaultCount} (esperado: 5)");
    printResult($delayCorrect, "retryDelay default = {$defaultDelay}ms (esperado: 1000)");
    printResult(true, "Ambos parámetros son opcionales (backwards compatible)");

    if ($countCorrect && $delayCorrect) $passedTests++;
} else {
    printResult(false, "Parámetros retryCount/retryDelay no encontrados en el constructor");
}


// ─────────────────────────────────────────────
//  Resumen Final
// ─────────────────────────────────────────────

echo PHP_EOL;
echo "╔═════════════════════════════════════════════════════════════════╗" . PHP_EOL;
echo "║                      RESUMEN DE RESULTADOS                    ║" . PHP_EOL;
echo "╠═════════════════════════════════════════════════════════════════╣" . PHP_EOL;
echo "║                                                               ║" . PHP_EOL;
printf("║   Tests ejecutados:  %-3d                                      ║" . PHP_EOL, $totalTests);
printf("║   Tests exitosos:    %-3d                                      ║" . PHP_EOL, $passedTests);
printf("║   Tests fallidos:    %-3d                                      ║" . PHP_EOL, $totalTests - $passedTests);
echo "║                                                               ║" . PHP_EOL;

if ($passedTests === $totalTests) {
    echo "║   Estado: ✅ TODOS LOS TESTS PASARON EXITOSAMENTE            ║" . PHP_EOL;
} else {
    echo "║   Estado: ❌ ALGUNOS TESTS FALLARON                           ║" . PHP_EOL;
}

echo "║                                                               ║" . PHP_EOL;
echo "╚═════════════════════════════════════════════════════════════════╝" . PHP_EOL;
echo PHP_EOL;

