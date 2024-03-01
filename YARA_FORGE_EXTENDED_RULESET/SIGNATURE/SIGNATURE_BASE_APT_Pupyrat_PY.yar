rule SIGNATURE_BASE_APT_Pupyrat_PY : FILE
{
	meta:
		description = "Detects Pupy RAT"
		author = "Florian Roth (Nextron Systems)"
		id = "cdd689e3-437e-514d-a058-fad80ce0639e"
		date = "2017-02-17"
		modified = "2023-12-05"
		reference = "https://www.secureworks.com/blog/iranian-pupyrat-bites-middle-eastern-organizations"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_magichound.yar#L10-L29"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "b30bc3082be3229ea2ef5d7c51ab6f97df2f612c80c45892e1a13fde1fb56725"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "8d89f53b0a6558d6bb9cdbc9f218ef699f3c87dd06bc03dd042290dedc18cb71"

	strings:
		$x1 = "reflective_inject_dll" fullword ascii
		$x2 = "ImportError: pupy builtin module not found !" fullword ascii
		$x3 = "please start pupy from either it's exe stub or it's reflective DLLR;" fullword ascii
		$x4 = "[INJECT] inject_dll." fullword ascii
		$x5 = "import base64,zlib;exec zlib.decompress(base64.b64decode('eJzzcQz1c/ZwDbJVT87Py0tNLlHnAgA56wXS'))" fullword ascii
		$op1 = { 8b 42 0c 8b 78 14 89 5c 24 18 89 7c 24 14 3b fd }

	condition:
		( uint16(0)==0x5a4d and filesize <20000KB and 1 of them ) or (2 of them )
}
