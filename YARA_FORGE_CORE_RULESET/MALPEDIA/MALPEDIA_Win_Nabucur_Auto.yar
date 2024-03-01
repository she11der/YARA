rule MALPEDIA_Win_Nabucur_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "01e16fcc-e93c-502a-bf23-e97657c28f28"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nabucur"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.nabucur_auto.yar#L1-L161"
		license_url = "N/A"
		logic_hash = "6100efc8bca15f40de853b2fa2bd4731e512123d488b941f31d2f09287a69887"
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
		$sequence_0 = { 48 49 85c0 75fa }
		$sequence_1 = { 48 5f 894500 5d }
		$sequence_2 = { 48 83e908 85c0 75f0 57 }
		$sequence_3 = { 48 83e904 85c0 7ff3 8bf0 8b442448 }
		$sequence_4 = { 48 83f801 89442418 0f8f15ffffff }
		$sequence_5 = { 33ff 33f6 4a c744244001000000 }
		$sequence_6 = { 009eaa030000 0fb686aa030000 57 83f80a 0f876d010000 }
		$sequence_7 = { 48 8906 8d442410 50 }
		$sequence_8 = { ba86a33ffb 83e904 ba575a2bfd eb69 83f901 7519 }
		$sequence_9 = { 3f 71e3 0c42 869576f1896a 86f6 }
		$sequence_10 = { 732e 5c 54 7346 b654 8c534c }
		$sequence_11 = { 141b 46 ec 54 732e }
		$sequence_12 = { 01e4 01f4 1481 0491 00850cf41196 }
		$sequence_13 = { ff75f8 ff35???????? ff15???????? 8b7520 8b45e4 }
		$sequence_14 = { 8b4608 50 ff15???????? 61 eb11 }
		$sequence_15 = { 06 e409 9a1496099a1581 0d911c9060 9d 01e4 }

	condition:
		7 of them and filesize <1949696
}