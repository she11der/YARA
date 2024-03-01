rule SIGNATURE_BASE_Webshell_H4Ntu_Shell__Powered_By_Tsoi_
{
	meta:
		description = "PHP Webshells Github Archive - file h4ntu shell [powered by tsoi].php"
		author = "Florian Roth (Nextron Systems)"
		id = "5a12a025-6497-545a-8da0-423ef448e374"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L5741-L5757"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "cbca8cd000e705357e2a7e0cf8262678706f18f9"
		logic_hash = "da5994e3278278920d3e4774850d9b05f0244d2af03d0de92d1466f6f87ca3eb"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s11 = "<title>h4ntu shell [powered by tsoi]</title>" fullword
		$s13 = "$cmd = $_POST['cmd'];" fullword
		$s16 = "$uname = posix_uname( );" fullword
		$s17 = "if(!$whoami)$whoami=exec(\"whoami\");" fullword
		$s18 = "echo \"<p><font size=2 face=Verdana><b>This Is The Server Information</b></font>"
		$s20 = "ob_end_clean();" fullword

	condition:
		3 of them
}
