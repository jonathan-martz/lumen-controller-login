<?php

namespace App\Http\Controllers;

use Laravel\Lumen\Routing\Controller as BaseController;

class LoginController extends BaseController
{
	/**
	 * @param  Request  $request
	 * @return Response
	 */
	public function user(Request $request)
	{
		return 'Konalo';
	}
}
