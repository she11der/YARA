rule SIGNATURE_BASE_FE_LEGALSTRIKE_MACRO
{
	meta:
		description = "This rule is designed to identify macros with the specific encoding used in the sample 30f149479c02b741e897cdb9ecd22da7."
		author = "Ian.Ahl@fireeye.com @TekDefense - modified by Florian Roth"
		id = "eb15e5aa-16e5-5c07-a293-ad15c0c09d8e"
		date = "2017-06-02"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_apt19.yar#L34-L50"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "b38edeedcc02168d3ba7e82c3f5c6963ffc8ce1688eeb424ce686484f3687512"
		score = 75
		quality = 85
		tags = ""
		version = ".1"
		filetype = "MACRO"

	strings:
		$ob1 = "ChrW(114) & ChrW(101) & ChrW(103) & ChrW(115) & ChrW(118) & ChrW(114) & ChrW(51) & ChrW(50) & ChrW(46) & ChrW(101)" ascii wide
		$wsobj1 = "Set Obj = CreateObject(\"WScript.Shell\")" ascii wide
		$wsobj2 = "Obj.Run " ascii wide

	condition:
		all of them
}
