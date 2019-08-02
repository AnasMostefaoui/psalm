<?php
namespace Psalm\Tests;

use Psalm\Config;
use Psalm\Context;

class TaintTest extends TestCase
{
    /**
     * @return void
     */
    public function testTaintedInputFromReturnType()
    {
        $this->expectException(\Psalm\Exception\CodeException::class);
        $this->expectExceptionMessage('TaintedInput');

        $this->project_analyzer->trackTaintedInputs();

        $this->addFile(
            'somefile.php',
            '<?php
                class A {
                    public function getUserId() : string {
                        return (string) $_GET["user_id"];
                    }

                    public function getAppendedUserId() : string {
                        return "aaaa" . $this->getUserId();
                    }

                    public function deleteUser(PDO $pdo) : void {
                        $userId = $this->getAppendedUserId();
                        $pdo->exec("delete from users where user_id = " . $userId);
                    }
                }'
        );

        $this->analyzeFile('somefile.php', new Context());
    }

    /**
     * @return void
     */
    public function testTaintedInputFromParam()
    {
        $this->expectException(\Psalm\Exception\CodeException::class);
        $this->expectExceptionMessage('TaintedInput');

        $this->project_analyzer->trackTaintedInputs();

        $this->addFile(
            'somefile.php',
            '<?php
                class A {
                    public function getUserId() : string {
                        return (string) $_GET["user_id"];
                    }

                    public function getAppendedUserId() : string {
                        return "aaaa" . $this->getUserId();
                    }

                    public function doDelete(PDO $pdo) : void {
                        $userId = $this->getAppendedUserId();
                        $this->deleteUser($pdo, $userId);
                    }

                    public function deleteUser(PDO $pdo, string $userId) : void {
                        $pdo->exec("delete from users where user_id = " . $userId);
                    }
                }'
        );

        $this->analyzeFile('somefile.php', new Context());
    }

    /**
     * @return void
     */
    public function testTaintedInputToParam()
    {
        $this->expectException(\Psalm\Exception\CodeException::class);
        $this->expectExceptionMessage('TaintedInput');

        $this->project_analyzer->trackTaintedInputs();

        $this->addFile(
            'somefile.php',
            '<?php
                class A {
                    public function getUserId(PDO $pdo) : void {
                        $this->deleteUser(
                            $pdo,
                            $this->getAppendedUserId((string) $_GET["user_id"])
                        );
                    }

                    public function getAppendedUserId(string $user_id) : string {
                        return "aaa" . $user_id;
                    }

                    public function deleteUser(PDO $pdo, string $userId) : void {
                        $pdo->exec("delete from users where user_id = " . $userId);
                    }
                }'
        );

        $this->analyzeFile('somefile.php', new Context());
    }

    /**
     * @return void
     */
    public function testTaintedInParentLoader()
    {
        $this->expectException(\Psalm\Exception\CodeException::class);
        $this->expectExceptionMessage('TaintedInput');

        $this->project_analyzer->trackTaintedInputs();

        $this->addFile(
            'somefile.php',
            '<?php
                abstract class A {
                    abstract public static function loadPartial(string $sink) : void;

                    public static function loadFull(string $sink) : void {
                        static::loadPartial($sink);
                    }
                }

                function getPdo() : PDO {
                    return new PDO("connectionstring");
                }

                class AChild extends A {
                    public static function loadPartial(string $sink) : void {
                        getPdo()->exec("select * from foo where bar = " . $sink);
                    }
                }

                class AGrandChild extends AChild {}

                class C {
                    public function foo(string $user_id) : void {
                        AGrandChild::loadFull($user_id);
                    }
                }

                (new C)->foo((string) $_GET["user_id"]);'
        );

        $this->analyzeFile('somefile.php', new Context());
    }

    /**
     * @return void
     */
    public function testValidatedInputFromParam()
    {
        $this->project_analyzer->trackTaintedInputs();

        $this->addFile(
            'somefile.php',
            '<?php
                /**
                 * @psalm-assert-untainted $userId
                 */
                function validateUserId(string $userId) : void {
                    if (!is_numeric($userId)) {
                        throw new \Exception("bad");
                    }
                }

                class A {
                    public function getUserId() : string {
                        return (string) $_GET["user_id"];
                    }

                    public function doDelete(PDO $pdo) : void {
                        $userId = $this->getUserId();
                        validateUserId($userId);
                        $this->deleteUser($pdo, $userId);
                    }

                    public function deleteUser(PDO $pdo, string $userId) : void {
                        $pdo->exec("delete from users where user_id = " . $userId);
                    }
                }'
        );

        $this->analyzeFile('somefile.php', new Context());
    }

    /**
     * @return void
     */
    public function testUntaintedInput()
    {
        $this->project_analyzer->trackTaintedInputs();

        $this->addFile(
            'somefile.php',
            '<?php
                class A {
                    public function getUserId() : int {
                        return (int) $_GET["user_id"];
                    }

                    public function getAppendedUserId() : string {
                        return "aaaa" . $this->getUserId();
                    }

                    public function deleteUser(PDO $pdo) : void {
                        $userId = $this->getAppendedUserId();
                        $pdo->exec("delete from users where user_id = " . $userId);
                    }
                }'
        );

        $this->analyzeFile('somefile.php', new Context());
    }
}
