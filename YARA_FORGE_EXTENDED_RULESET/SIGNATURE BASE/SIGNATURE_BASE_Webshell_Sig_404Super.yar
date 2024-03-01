rule SIGNATURE_BASE_Webshell_Sig_404Super
{
	meta:
		description = "Web shells - generated from file 404super.php"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-03-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L3296-L3314"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "7ed63176226f83d36dce47ce82507b28"
		logic_hash = "01ecffc6bca2acf1ea4f4d965f3513f7b08ee3d5abbda29d53081f2931ecf9e9"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s4 = "$i = pack('c*', 0x70, 0x61, 99, 107);" fullword
		$s6 = "    'h' => $i('H*', '687474703a2f2f626c616b696e2e64756170702e636f6d2f7631')," fullword
		$s7 = "//http://require.duapp.com/session.php" fullword
		$s8 = "if(!isset($_SESSION['t'])){$_SESSION['t'] = $GLOBALS['f']($GLOBALS['h']);}" fullword
		$s12 = "//define('pass','123456');" fullword
		$s13 = "$GLOBALS['c']($GLOBALS['e'](null, $GLOBALS['s']('%s',$GLOBALS['p']('H*',$_SESSIO"

	condition:
		1 of them
}
