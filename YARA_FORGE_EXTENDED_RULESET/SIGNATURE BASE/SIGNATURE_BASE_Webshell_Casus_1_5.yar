rule SIGNATURE_BASE_Webshell_Casus_1_5
{
	meta:
		description = "PHP Webshells Github Archive - file CasuS 1.5.php"
		author = "Florian Roth (Nextron Systems)"
		id = "cf89d8f8-d498-57fe-98eb-a98350db182f"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L6708-L6721"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "7eee8882ad9b940407acc0146db018c302696341"
		logic_hash = "0dbaa39bd33047d24e5bc9716108c5581da3f54e93d90f9c550b3d84de1ebfe2"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = "<font size='+1'color='#0000FF'><u>CasuS 1.5'in URL'si</u>: http://$HTTP_HO"
		$s8 = "$fonk_kap = get_cfg_var(\"fonksiyonlary_kapat\");" fullword
		$s18 = "if (file_exists(\"F:\\\\\")){" fullword

	condition:
		1 of them
}
