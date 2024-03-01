rule SIGNATURE_BASE__Root_040_Zip_Folder_Deploy
{
	meta:
		description = "Webshells Auto-generated - file deploy.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "7e592ab2-8a53-59d5-a45d-971398586479"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L8754-L8767"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "2c9f9c58999256c73a5ebdb10a9be269"
		logic_hash = "9852b105e6a28f5500fc6739b196dd14b9b0b69b1077be4063735380b0699abb"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s5 = "halon synscan 127.0.0.1 1-65536"
		$s8 = "Obviously you replace the ip address with that of the target."

	condition:
		all of them
}
