rule MALPEDIA_Win_Dadstache_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "1b258f10-8f88-5091-9d8a-b7cbb1e4a0e5"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dadstache"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.dadstache_auto.yar#L1-L168"
		license_url = "N/A"
		logic_hash = "77711feda2c16f34186a4f1ae2717975593af55ed7e01d177132f4e333f94d90"
		score = 75
		quality = 75
		tags = "FILE"
		version = "1"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"

	strings:
		$sequence_0 = { 8d442414 50 6a1f ff35???????? }
		$sequence_1 = { 8b470c 8bf9 31460c 0f1006 c7450c09000000 0f1145e8 }
		$sequence_2 = { 85c0 7550 8b0d???????? 8b35???????? 85c9 7403 }
		$sequence_3 = { 53 8d4d08 895d08 51 53 50 53 }
		$sequence_4 = { 837c242c10 8d442418 51 0f4344241c }
		$sequence_5 = { 8d5201 8842ff 83e901 75f2 8bd3 c1ea04 }
		$sequence_6 = { 6aff 6a00 8d442438 c74424340f000000 50 }
		$sequence_7 = { 6a1f ff35???????? ff15???????? a1???????? }
		$sequence_8 = { 741b 8b45f0 47 83c628 3bf8 }
		$sequence_9 = { 7405 8b4718 8901 8b731c 57 }
		$sequence_10 = { 42 83c628 8955f0 3b55e4 0f8c66ffffff }
		$sequence_11 = { 7325 8b7c240c 4a 03d7 8d4fff }
		$sequence_12 = { 8b4485b0 85d2 8b56f8 7405 0d00020000 8d5de4 53 }
		$sequence_13 = { e8???????? 85c0 741d 8bce e8???????? 8bce }
		$sequence_14 = { c3 8b4e04 8d4604 8945fc 8b06 }
		$sequence_15 = { 84c9 740e 3aca 74ef 0fb6c2 0fb6c9 }

	condition:
		7 of them and filesize <580608
}
