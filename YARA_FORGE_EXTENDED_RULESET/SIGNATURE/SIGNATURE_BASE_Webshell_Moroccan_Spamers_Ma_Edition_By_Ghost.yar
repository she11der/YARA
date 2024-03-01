rule SIGNATURE_BASE_Webshell_Moroccan_Spamers_Ma_Edition_By_Ghost
{
	meta:
		description = "PHP Webshells Github Archive - file Moroccan Spamers Ma-EditioN By GhOsT.php"
		author = "Florian Roth (Nextron Systems)"
		id = "4fa9ce70-d300-55fe-bf98-636f026317ec"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L6155-L6168"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "31e5473920a2cc445d246bc5820037d8fe383201"
		logic_hash = "0e3d2d97665b8849d121d63a22baf7393047a814dde3753e395418c1868b59be"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s4 = "$content = chunk_split(base64_encode($content)); " fullword
		$s12 = "print \"Sending mail to $to....... \"; " fullword
		$s16 = "if (!$from && !$subject && !$message && !$emaillist){ " fullword

	condition:
		all of them
}
