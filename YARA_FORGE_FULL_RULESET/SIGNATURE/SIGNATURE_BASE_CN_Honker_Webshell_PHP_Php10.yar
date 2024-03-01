rule SIGNATURE_BASE_CN_Honker_Webshell_PHP_Php10 : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file php10.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "5fe78cc6-8be3-595f-a082-e361259938e5"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_webshells.yar#L655-L670"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "3698c566a0ae07234c8957112cdb34b79362b494"
		logic_hash = "76bb2dfd518173f031cc3c93b2098edaef4aca09f0dd8228223257b0b7df452b"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "dumpTable($N,$M,$Hc=false){if($_POST[\"format\"]!=\"sql\"){echo\"\\xef\\xbb\\xbf" ascii
		$s2 = "';if(DB==\"\"||!$od){echo\"<a href='\".h(ME).\"sql='\".bold(isset($_GET[\"sql\"]" ascii

	condition:
		filesize <600KB and all of them
}
