rule GCTI_Cobaltstrike_Resources_Template_Py_V3_3_To_V4_X
{
	meta:
		description = "Cobalt Strike's resources/template.py signature for versions v3.3 to v4.x"
		author = "gssincla@google.com"
		id = "16aef9a9-b217-5462-93dc-f6273c99ddd0"
		date = "2022-11-18"
		modified = "2022-11-19"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Template_Py_v3_3_to_v4_x.yara#L17-L36"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "d5cb406bee013f51d876da44378c0a89b7b3b800d018527334ea0c5793ea4006"
		logic_hash = "3c26cea4b8f2b200bf58e939ae9ead7a7339d4ec0de8c72b3d9c7da897600081"
		score = 75
		quality = 85
		tags = ""

	strings:
		$arch = "platform.architecture()"
		$nope = "WindowsPE"
		$alloc = "ctypes.windll.kernel32.VirtualAlloc"
		$movemem = "ctypes.windll.kernel32.RtlMoveMemory"
		$thread = "ctypes.windll.kernel32.CreateThread"
		$wait = "ctypes.windll.kernel32.WaitForSingleObject"

	condition:
		all of them
}