<?php
namespace Psalm\Tests;

use Psalm\Config;
use Psalm\Context;

class TaintTest extends TestCase
{
    /**
     * @return void
     */
    public function testTaintedInput()
    {
        $this->expectException(\Psalm\Exception\CodeException::class);
        $this->expectExceptionMessage('TaintedInput');

        $this->project_analyzer->check_tainted_inputs = true;

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
    public function testUntainedInput()
    {
        $this->project_analyzer->check_tainted_inputs = true;

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
}
