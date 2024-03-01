import "pe"

rule SIGNATURE_BASE_Corkowdll : FILE
{
	meta:
		description = "Rule to detect the Corkow DLL files"
		author = "Group IB"
		id = "cc9d2bb3-8db3-54a0-bd05-7f054ce84633"
		date = "2016-01-02"
		modified = "2023-12-05"
		reference = "https://www.group-ib.ru/brochures/Group-IB-Corkow-Report-EN.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/crime_corkow_dll.yar#L3-L24"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "072112c79f20ba08b7ef71d3dacff7eb947b4a27bf6381ce788e229f2f791cdf"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$binary1 = { 60 [0-8] 9C [0-8] BB ?? ?? ?? ?? [0-8] 81 EB ?? ?? ?? ?? [0-8] E8 ?? 00 00 00 [0-8] 58 [0-8] 2B C3 }
		$binary2 = { (FF 75 ?? | 53) FF 75 10 FF 75 0C FF 75 08 E8 ?? ?? ?? ?? [3-9] C9 C2 0C 00 }

	condition:
		uint16(0)==0x5a4d and ( all of ($binary*) and (pe.exports("Control_RunDLL") or pe.exports("ServiceMain") or pe.exports("DllGetClassObject")) or (pe.exports("ServiceMain") and pe.exports("Control_RunDLL")))
}
