rule SIGNATURE_BASE_Powershell_Case_Anomaly : FILE
{
	meta:
		description = "Detects obfuscated PowerShell hacktools"
		author = "Florian Roth (Nextron Systems)"
		id = "41c97d15-c167-5bdd-a8b4-871d14f66fe1"
		date = "2017-08-11"
		modified = "2022-06-12"
		reference = "https://twitter.com/danielhbohannon/status/905096106924761088"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_case_anomalies.yar#L11-L60"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "cbef94b899a2d22930ee0e8b3eac03c505db629d19a62ddd8f56482403dfa595"
		score = 70
		quality = 77
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "powershell" nocase ascii wide
		$sn1 = "powershell" ascii wide
		$sn2 = "Powershell" ascii wide
		$sn3 = "PowerShell" ascii wide
		$sn4 = "POWERSHELL" ascii wide
		$sn5 = "powerShell" ascii wide
		$sn6 = "PowerShelL" ascii wide
		$sn7 = "PowershelL" ascii wide
		$a1 = "wershell -e " nocase wide ascii
		$an1 = "wershell -e " wide ascii
		$an2 = "werShell -e " wide ascii
		$k1 = "-noprofile" fullword nocase ascii wide
		$kn1 = "-noprofile" ascii wide
		$kn2 = "-NoProfile" ascii wide
		$kn3 = "-noProfile" ascii wide
		$kn4 = "-NOPROFILE" ascii wide
		$kn5 = "-Noprofile" ascii wide
		$fp1 = "Microsoft Code Signing" ascii fullword
		$fp2 = "Microsoft Corporation" ascii
		$fp3 = "Microsoft.Azure.Commands.ContainerInstance" wide
		$fp4 = "# Localized PSGet.Resource.psd1" wide

	condition:
		filesize <800KB and ((#s1>#sn1+#sn2+#sn3+#sn4+#sn5+#sn6+#sn7) or (#a1>#an1+#an2) or (#k1>#kn1+#kn2+#kn3+#kn4+#kn5)) and not 1 of ($fp*)
}
