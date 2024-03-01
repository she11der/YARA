rule MALPEDIA_Win_Hamweq_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "5d79f276-5807-56d4-9ea0-44042b180646"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hamweq"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.hamweq_auto.yar#L1-L117"
		license_url = "N/A"
		logic_hash = "f4464ade23ea171530cd0c6e2b15abfaf45c0eb2379ccacb80bd385a306f9a8e"
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
		$sequence_0 = { 53 51 8b4e08 8945f8 ffb148010000 ff5044 }
		$sequence_1 = { 8d85e4f1ffff 50 ff5744 50 }
		$sequence_2 = { 837c910800 8d449108 894514 0f8438010000 837c910c00 }
		$sequence_3 = { 668b4804 51 ff30 56 e8???????? 83c40c }
		$sequence_4 = { 51 ff5040 8b0e 8d85ecfeffff 53 50 }
		$sequence_5 = { 7504 6afe ebea 8b4e08 8b06 ff7170 }
		$sequence_6 = { 8d4580 8b0b 50 ff5154 }
		$sequence_7 = { 8b06 753c ffb1d8000000 8d8d00feffff 51 }
		$sequence_8 = { 51 8d4d80 51 ff5054 eb12 8b5d08 }
		$sequence_9 = { c3 8b442408 8a08 84c9 7408 }

	condition:
		7 of them and filesize <24576
}
