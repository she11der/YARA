rule SIGNATURE_BASE_Empire_Powershell_Framework_Gen2 : FILE
{
	meta:
		description = "Detects Empire component"
		author = "Florian Roth (Nextron Systems)"
		id = "eab277ca-0dd4-5035-82aa-1ac2120bac94"
		date = "2016-11-05"
		modified = "2023-12-05"
		reference = "https://github.com/adaptivethreat/Empire"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_empire.yar#L409-L428"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "e3cb63d0c3278ee4d04cb4b1d6ebe817fb3da97d25e2581f95bd43ecd5142b30"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "1be3e3ec0e364db0c00fad2c59c7041e23af4dd59c4cc7dc9dcf46ca507cd6c8"
		hash3 = "a3428a7d4f9e677623fadff61b2a37d93461123535755ab0f296aa3b0396eb28"
		hash5 = "4725a57a5f8b717ce316f104e9472e003964f8eae41a67fd8c16b4228e3d00b3"
		hash6 = "61e5ca9c1e8759a78e2c2764169b425b673b500facaca43a26c69ff7e09f62c4"
		hash8 = "eaff29dd0da4ac258d85ecf8b042d73edb01b4db48c68bded2a8b8418dc688b5"

	strings:
		$x1 = "$DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)" fullword ascii
		$s20 = "#Shellcode: CallDllMain.asm" fullword ascii

	condition:
		( uint16(0)==0x7566 and filesize <4000KB and 1 of them ) or all of them
}
