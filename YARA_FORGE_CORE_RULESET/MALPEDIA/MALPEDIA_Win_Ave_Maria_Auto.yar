rule MALPEDIA_Win_Ave_Maria_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "410b5f16-91ac-5311-b6ab-598dd1954c39"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ave_maria"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.ave_maria_auto.yar#L1-L129"
		license_url = "N/A"
		logic_hash = "d6a2fe1f05fe69e9ea5ce04e4093200d3e962df5b8f3c4c00fc93efedbc85567"
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
		$sequence_0 = { 8b07 ff740610 8d4614 50 8d45f8 50 }
		$sequence_1 = { 52 8b08 6a01 50 ff510c 85c0 74c1 }
		$sequence_2 = { 6a0a 03c1 59 8bf8 f3a5 8d4d30 }
		$sequence_3 = { 0f57c0 c745e015000000 50 8d4de0 0f1145e8 e8???????? 8bc8 }
		$sequence_4 = { 803800 7509 33c0 5b c3 33c0 40 }
		$sequence_5 = { 8bc7 99 2bc1 8bcf 1bd6 52 50 }
		$sequence_6 = { ff500c 8b06 68???????? ff37 8b08 }
		$sequence_7 = { 51 54 8bce e8???????? 8b4d08 e8???????? 83c410 }
		$sequence_8 = { 300431 41 3bcf 7ced 5f 8bc6 5e }
		$sequence_9 = { 83ec18 53 8bd9 56 57 895df8 }

	condition:
		7 of them and filesize <237568
}
