rule SIGNATURE_BASE_Webshell_PHP_G5
{
	meta:
		description = "Web Shell - file G5.php"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L1378-L1391"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "95b4a56140a650c74ed2ec36f08d757f"
		logic_hash = "2edffbea5142ef146cec57cb88b473532f56ab3e95151c5648eaeabe6a75feda"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s3 = "echo \"Hacking Mode?<br><select name='htype'><option >--------SELECT--------</op"

	condition:
		all of them
}
