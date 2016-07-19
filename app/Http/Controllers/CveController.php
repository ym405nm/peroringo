<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

use App\Http\Requests;
use App\Http\Resposne;

use App\Cve;

use Goutte\Client;
use Mockery\CountValidator\Exception;

class CveController extends Controller {
	public function api( Request $request ) {
		$input_text = $request->input( "text" );
		$input_user = $request->input( "user_name" );
		// slackbot は無視
		if ( "slackbot" === $input_user ) {
			\Log::info( "bot検知" . $input_text );

			return;
		}
		// CVE番号が含まれていないと無視
		if ( preg_match( "/CVE-[0-9]{4}-[0-9]{4,7}/i", $input_text, $match ) ) {
			$cve_number = $match[0];
			$cve_number = strtoupper( $cve_number ); // 小文字で来たクエリを大文字に変換
		} else {
			\Log::info( "該当記述なし" . $input_text );

			return;
		}
		$mitre_url = sprintf( "https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s", $cve_number );
		$cve       = Cve::all();
		$found     = $cve->where( "cve", $cve_number );
		if ( $found->count() != 0 ) {
			// CVEが見つかった場合
			$description = $found->first()->description;
			$url         = $found->first()->url;
			$text        = $cve_number . " は「" . $description . "」だよ " . $url . "\n" . $mitre_url;

			return \Response::json( array( "text" => $text ) );
		} else {
			// CVEが見つからなかった場合
			// JVNを検索しにいく
			try {
				$client       = new Client();
				$crawler      = $client->request( 'GET',
					'http://jvndb.jvn.jp/search/index.php?mode=_vulnerability_search_IA_VulnSearch&lang=ja&keyword=' . $cve_number );
				$url_list     = $crawler->filter( 'a' )->each( function ( $node ) {
					return $node->attr( "href" );
				} );
				$search_array = preg_grep( "/contents/", $url_list );
				if ( 0 < count( $search_array ) ) {
					// JNVから見つかった場合
					$content_url = "http://jvndb.jvn.jp" . current( $search_array );
					sleep( 1 );
					$client     = new Client();
					$crawler    = $client->request( 'GET', $content_url );
					$page_title = $crawler->filter( "h2" )->last()->text();
					\Log::info( $page_title );

					// ログをDBに保存する
					$save_cve              = new Cve;
					$save_cve->cve         = $cve_number;
					$save_cve->description = $page_title;
					$save_cve->url         = $content_url;
					$save_cve->save();

					$text = $cve_number . " は「" . $page_title . "」だよ " . $content_url."\n".$mitre_url;

					return \Response::json( array( "text" => $text ) );

				}
			} catch ( Exception $e ) {
				\Log::error( $e->getMessage() );
			}

			return \Response::json( array( "text" => $cve_number . " はJVNから見つからなかったよ。。。\n" . $mitre_url ) );
		}
	}
}

