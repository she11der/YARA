rule SIGNATURE_BASE_Webshell_Shell_Phpspy_2005_Full_Phpspy_2005_Lite_Phpspy_2006_Arabicspy_PHPSPY_Hkrkoz
{
	meta:
		description = "Web Shell"
		author = "Florian Roth (Nextron Systems)"
		id = "41a0560a-b22e-5028-8ad1-710c5758cb1d"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L2546-L2567"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "5da06481cf789e71969a5b54a33bfab41e08a1961cc056604a696203fef48422"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash0 = "791708057d8b429d91357d38edf43cc0"
		hash1 = "b68bfafc6059fd26732fa07fb6f7f640"
		hash2 = "42f211cec8032eb0881e87ebdb3d7224"
		hash3 = "40a1f840111996ff7200d18968e42cfe"
		hash4 = "e0202adff532b28ef1ba206cf95962f2"
		hash5 = "0712e3dc262b4e1f98ed25760b206836"
		hash6 = "802f5cae46d394b297482fd0c27cb2fc"

	strings:
		$s0 = "$mainpath_info           = explode('/', $mainpath);" fullword
		$s6 = "if (!isset($_GET['action']) OR empty($_GET['action']) OR ($_GET['action'] == \"d"

	condition:
		all of them
}
