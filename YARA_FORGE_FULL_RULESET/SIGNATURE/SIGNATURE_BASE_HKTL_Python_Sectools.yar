rule SIGNATURE_BASE_HKTL_Python_Sectools
{
	meta:
		description = "Detects code which uses the python lib sectools"
		author = "Arnim Rupp"
		id = "89a5e0ba-5547-53e4-84a3-d07ee779596e"
		date = "2023-01-27"
		modified = "2023-12-05"
		reference = "https://github.com/p0dalirius/sectools"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_susp_hacktool.yar#L18-L35"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "814ba1aa62bbb7aba886edae0f4ac5370818de15ca22a52a6ab667b4e93abf84"
		hash = "b3328ac397d311e6eb79f0a5b9da155c4d1987e0d67487ea681ea59d93641d9e"
		hash = "8cd205d5380278cff6673520439057e78fb8bf3d2b1c3c9be8463e949e5be4a1"
		logic_hash = "17f6897dc623f822c7ae6a7ae51714e78316d7b7fdf59b9f2f625ecaae939522"
		score = 50
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$import1 = "from sectools"
		$import2 = "import sectools"

	condition:
		any of ($import*)
}
