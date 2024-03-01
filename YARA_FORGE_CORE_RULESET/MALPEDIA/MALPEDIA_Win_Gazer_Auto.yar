rule MALPEDIA_Win_Gazer_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "4f697767-8c05-5c0d-bde5-d6a7fdfb5341"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.gazer"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.gazer_auto.yar#L1-L119"
		license_url = "N/A"
		logic_hash = "9d7c4a164f0a9c13470f23ca334f1d2575ebac4454f4b53ffe47ee33d23ce84e"
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
		$sequence_0 = { 85c0 7511 e8???????? 84c0 7508 }
		$sequence_1 = { 85c0 7511 e8???????? 84c0 7508 83c8ff e9???????? }
		$sequence_2 = { 85c0 7511 e8???????? 84c0 }
		$sequence_3 = { ff15???????? 85c0 7511 e8???????? 84c0 7508 83c8ff }
		$sequence_4 = { 7511 e8???????? 84c0 7508 83c8ff e9???????? }
		$sequence_5 = { ff15???????? 85c0 7511 e8???????? 84c0 7508 }
		$sequence_6 = { 7511 e8???????? 84c0 7508 83c8ff }
		$sequence_7 = { ff15???????? 85c0 7511 e8???????? 84c0 }
		$sequence_8 = { 85c0 7511 e8???????? 84c0 7508 83c8ff }
		$sequence_9 = { 4133c0 23c1 33c2 4103c1 }

	condition:
		7 of them and filesize <950272
}
