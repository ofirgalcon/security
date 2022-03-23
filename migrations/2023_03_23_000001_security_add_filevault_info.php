<?php
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Capsule\Manager as Capsule;

class SecurityAddFilevaultInfo extends Migration
{
    private $tableName = 'security';

    public function up()
    {
        $capsule = new Capsule();
        $capsule::schema()->table($this->tableName, function (Blueprint $table) {
          $table->boolean('filevault_status')->nullable();
          $table->string('filevault_users')->nullable();
          $table->index('filevault_status');
          $table->index('filevault_users');
          
        });
    }
    
    public function down()
    {
        $capsule = new Capsule();
        $capsule::schema()->table($this->tableName, function (Blueprint $table) {
            $table->dropColumn('filevault_status');
            $table->dropColumn('filevault_users');
        });
    }
}
