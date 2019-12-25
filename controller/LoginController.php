<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;

/**
 * Class LoginController
 * @package App\Http\Controllers
 */
class LoginController extends Controller
{

    /**
     * @return mixed
     * @todo move logic into own functions
     */
    public function user()
    {
        $validation = $this->validate($this->request, [
            'username' => 'required',
            'password' => 'required|min:8'
        ]);

        $this->addResult('username', $this->request->input('username'));

        $user = DB::table('users')
            ->where('username', '=', $this->request->input('username'))
            ->where('username_hash', '=', sha1($this->request->input('username')))
            ->first();

        $trys = DB::table('login_try')
            ->where('username', '=', $this->request->input('username'))
            ->where('username_hash', '=', sha1($this->request->input('username')))
            ->whereNotIn('status', ['success'])
            ->where('created_at', '>', time() - (60 * 60))
            ->count();

        if ($user->active === 1) {
            if ($trys < 10) {
                if ($user !== NULL) {
                    if (Hash::check($this->request->input('password'), $user->password)) {
                        $token = bin2hex(openssl_random_pseudo_bytes(256));

                        DB::table('login_try')
                            ->insert([
                                'username' => $this->request->input('username'),
                                'username_hash' => sha1($this->request->input('username')),
                                'status' => 'success',
                                'created_at' => time()
                            ]);

                        DB::table('auth_tokens')
                            ->insert([
                                'token' => $token,
                                'UID' => $user->id,
                                'created_at' => time()
                            ]);

                        $this->addMessage('success', 'User authenticated.');

                        $this->addResult('auth', [
                            'token' => $token,
                            'expires' => time() + (60 * 60 * 24 * 7)
                        ]);
                        $this->addResult('user', [
                            'username' => $user->username,
                            'email' => $user->email,
                            'id' => $user->id
                        ]);

                        return $this->getResponse();
                    } else {
                        DB::table('login_try')
                            ->insert([
                                'username' => $this->request->input('username'),
                                'username_hash' => sha1($this->request->input('username')),
                                'status' => 'failed',
                                'created_at' => time()
                            ]);
                        $this->addMessage('warning', 'User credentials wrong.');

                        return $this->getResponse();
                    }
                } else {
                    $this->addMessage('error', 'User doesnt exists.');

                    return $this->getResponse();
                }
            } else {
                DB::table('login_try')
                    ->insert([
                        'username' => $this->request->input('username'),
                        'username_hash' => sha1($this->request->input('username')),
                        'status' => 'blocked',
                        'created_at' => time()
                    ]);

                $this->addMessage('error', 'User login blocked.');

                $this->addResult('trys', $trys);

                return $this->getResponse();
            }
        } else {
            $this->addMessage('error', 'User is not activated yet. Please check your Emails to activate it or Request a new Eamil.');
        }
    }
}
