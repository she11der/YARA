rule SIGNATURE_BASE_Webshell_C99_C66_C99_Shadows_Mod_C99Shell
{
	meta:
		description = "Web Shell - from files c99.php, c66.php, c99-shadows-mod.php, c99shell.php"
		author = "Florian Roth (Nextron Systems)"
		id = "ce88027c-ae08-59f3-948d-6f3d58515468"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L2860-L2882"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "b50a6124f25bbb6fcc9d16d1de26d833a4b968db8e8033e76f3a74695577017e"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash0 = "61a92ce63369e2fa4919ef0ff7c51167"
		hash1 = "0f5b9238d281bc6ac13406bb24ac2a5b"
		hash2 = "68c0629d08b1664f5bcce7d7f5f71d22"
		hash3 = "048ccc01b873b40d57ce25a4c56ea717"

	strings:
		$s2 = "  if (unlink(_FILE_)) {@ob_clean(); echo \"Thanks for using c99shell v.\".$shv"
		$s3 = "  \"c99sh_backconn.pl\"=>array(\"Using PERL\",\"perl %path %host %port\")," fullword
		$s4 = "<br><TABLE style=\"BORDER-COLLAPSE: collapse\" cellSpacing=0 borderColorDark=#66"
		$s7 = "   elseif (!$data = c99getsource($bind[\"src\"])) {echo \"Can't download sources"
		$s8 = "  \"c99sh_datapipe.pl\"=>array(\"Using PERL\",\"perl %path %localport %remotehos"
		$s9 = "   elseif (!$data = c99getsource($bc[\"src\"])) {echo \"Can't download sources!"

	condition:
		2 of them
}
