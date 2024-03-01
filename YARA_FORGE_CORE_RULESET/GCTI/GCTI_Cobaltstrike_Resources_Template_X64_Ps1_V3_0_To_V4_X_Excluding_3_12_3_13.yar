rule GCTI_Cobaltstrike_Resources_Template_X64_Ps1_V3_0_To_V4_X_Excluding_3_12_3_13
{
	meta:
		description = "Cobalt Strike's resources/template.x64.ps1, resources/template.hint.x64.ps1 and resources/template.hint.x32.ps1 from v3.0 to v4.x except 3.12 and 3.13"
		author = "gssincla@google.com"
		id = "5a808113-aacb-56ca-b3ec-166c73c54b85"
		date = "2022-11-18"
		modified = "2022-11-19"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Template_x64_Ps1_v3_0_to_v4_x_excluding_3_12_3_13.yara#L17-L37"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "ff743027a6bcc0fee02107236c1f5c96362eeb91f3a5a2e520a85294741ded87"
		logic_hash = "80823b8590004686ebd83958cad16094ea2f6958a837d87934507531a00df77a"
		score = 75
		quality = 81
		tags = ""

	strings:
		$dda = "[AppDomain]::CurrentDomain.DefineDynamicAssembly" nocase
		$imm = "InMemoryModule" nocase
		$mdt = "MyDelegateType" nocase
		$rd = "New-Object System.Reflection.AssemblyName('ReflectedDelegate')" nocase
		$data = "[Byte[]]$var_code = [System.Convert]::FromBase64String(" nocase
		$64bitSpecific = "[IntPtr]::size -eq 8"
		$mandatory = "Mandatory = $True"

	condition:
		all of them
}
