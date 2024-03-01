rule GCTI_Cobaltstrike_Resources_Template__X32_X64_Ps1_V1_45_To_V2_5_And_V3_11_To_V3_14
{
	meta:
		description = "Cobalt Strike's resources/template.x64.ps1, resources/template.x32 from v3.11 to v3.14 and resources/template.ps1 from v1.45 to v2.5 "
		author = "gssincla@google.com"
		id = "c9fa6a39-0098-5dde-9762-94bc6b2df299"
		date = "2022-11-18"
		modified = "2022-11-19"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Template__x32_x64_Ps1_v1_45_to_v2_5_and_v3_11_to_v3_14.yara#L17-L43"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "ff743027a6bcc0fee02107236c1f5c96362eeb91f3a5a2e520a85294741ded87"
		logic_hash = "5196f111f257239d2e7e4ca342e7fc8bac1687743bc8c7ff23addf1f094b2e93"
		score = 75
		quality = 85
		tags = ""

	strings:
		$importVA = "[DllImport(\"kernel32.dll\")] public static extern IntPtr VirtualAlloc" nocase
		$importCT = "[DllImport(\"kernel32.dll\")] public static extern IntPtr CreateThread" nocase
		$importWFSO = "[DllImport(\"kernel32.dll\")] public static extern int WaitForSingleObject" nocase
		$compiler = "New-Object Microsoft.CSharp.CSharpCodeProvider" nocase
		$params = "New-Object System.CodeDom.Compiler.CompilerParameters" nocase
		$paramsSys32 = ".ReferencedAssemblies.AddRange(@(\"System.dll\", [PsObject].Assembly.Location))" nocase
		$paramsGIM = ".GenerateInMemory = $True" nocase
		$result = "$compiler.CompileAssemblyFromSource($params, $assembly)" nocase

	condition:
		all of them
}
