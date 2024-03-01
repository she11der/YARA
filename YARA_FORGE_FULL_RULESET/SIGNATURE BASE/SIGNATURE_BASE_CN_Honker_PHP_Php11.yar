rule SIGNATURE_BASE_CN_Honker_PHP_Php11 : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file php11.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "e20eaab1-9799-5e61-9a25-3ac0dcce5f7f"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L2001-L2017"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "dcc8226e7eb20e4d4bef9e263c14460a7ee5e030"
		logic_hash = "d32b0540521a6b1d65c224bdee463813d72846c26f27326a092bdf3b90c3ae7c"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "<tr><td><b><?php if (!$win) {echo wordwrap(myshellexec('id'),90,'<br>',1);} else" ascii
		$s2 = "foreach (glob($_GET['pathtomass'].\"/*.htm\") as $injectj00) {" fullword ascii
		$s3 = "echo '[cPanel Found] '.$login.':'.$pass.\"  Success\\n\";" fullword ascii

	condition:
		filesize <800KB and all of them
}
