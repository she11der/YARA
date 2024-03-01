rule SIGNATURE_BASE_Webshell__Cyber_Shell_Cybershell_Cyber_Shell__V_1_0_
{
	meta:
		description = "PHP Webshells Github Archive - from files Cyber Shell.php, cybershell.php, Cyber Shell (v 1.0).php"
		author = "Florian Roth (Nextron Systems)"
		id = "79146f25-87b9-5216-af88-4e433bb08b90"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L6737-L6754"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "fc2cf9a25ccc5aa3d9dc287ef9600b065ba9025cfb0a1ccca1bce9120ea03ff4"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash0 = "ef7f7c45d26614cea597f2f8e64a85d54630fe38"
		hash1 = "cabf47b96e3b2c46248f075bdbc46197db28a25f"
		hash2 = "9e165d4ed95e0501cd9a90155ac60546eb5b1076"

	strings:
		$s4 = " <a href=\"http://www.cyberlords.net\" target=\"_blank\">Cyber Lords Community</"
		$s10 = "echo \"<meta http-equiv=Refresh content=\\\"0; url=$PHP_SELF?edit=$nameoffile&sh"
		$s11 = " *   Coded by Pixcher" fullword
		$s16 = "<input type=text size=55 name=newfile value=\"$d/newfile.php\">" fullword

	condition:
		2 of them
}
