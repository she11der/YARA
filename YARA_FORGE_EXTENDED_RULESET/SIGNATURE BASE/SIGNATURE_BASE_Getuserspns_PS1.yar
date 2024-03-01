rule SIGNATURE_BASE_Getuserspns_PS1
{
	meta:
		description = "Auto-generated rule - file GetUserSPNs.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "a2fba75c-264f-5e89-afaf-9d19a4a90784"
		date = "2016-05-21"
		modified = "2023-12-05"
		reference = "https://github.com/skelsec/PyKerberoast"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_kerberoast.yar#L25-L41"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "204b009677a02bf8725f928c2bfff321b4543a883760e312a0c92f187684c8e9"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "1b69206b8d93ac86fe364178011723f4b1544fff7eb1ea544ab8912c436ddc04"

	strings:
		$s1 = "$ForestInfo = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()" fullword ascii
		$s2 = "@{Name=\"PasswordLastSet\";      Expression={[datetime]::fromFileTime($result.Properties[\"pwdlastset\"][0])} } #, `" fullword ascii
		$s3 = "Write-Host \"No Global Catalogs Found!\"" fullword ascii
		$s4 = "$searcher.PropertiesToLoad.Add(\"pwdlastset\") | Out-Null" fullword ascii

	condition:
		2 of them
}
