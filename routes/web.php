<?php

use Illuminate\Support\Facades\Route;

Route::post('/user/login', [
    'middleware' => ['xss', 'https'],
    'uses' => 'App\Http\Controllers\LoginController@user'
]);
