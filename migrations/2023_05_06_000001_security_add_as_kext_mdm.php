<?php
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Capsule\Manager as Capsule;

class SecurityAddAsKextMdm extends Migration
{
    private $tableName = 'security';

    public function up()
    {
        $capsule = new Capsule();
        $capsule::schema()->table($this->tableName, function (Blueprint $table) {
          $table->string('as_third_party_kexts')->nullable();
          $table->string('as_user_mdm_control')->nullable();
          $table->string('as_dep_mdm_control')->nullable();          
        });
    }

    public function down()
    {
        $capsule = new Capsule();
        $capsule::schema()->table($this->tableName, function (Blueprint $table) {
            $table->dropColumn('as_third_party_kexts');
            $table->dropColumn('as_user_mdm_control');
            $table->dropColumn('as_dep_mdm_control');
        });
    }
}
