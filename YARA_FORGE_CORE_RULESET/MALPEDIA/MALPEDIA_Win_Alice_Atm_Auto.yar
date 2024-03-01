rule MALPEDIA_Win_Alice_Atm_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "66f601ee-4bc7-50a3-954d-4444abf4a52f"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.alice_atm"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.alice_atm_auto.yar#L1-L118"
		license_url = "N/A"
		logic_hash = "5f587bc558ca0a42c8c96fe5a1cfb47b3decdd71da86c983392de940e1606224"
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
		$sequence_0 = { ff75f8 8f45fc ff7508 e8???????? 8b45fc }
		$sequence_1 = { 0fb7c0 8945f8 8b7d10 83ff00 0f86c2000000 }
		$sequence_2 = { c9 c20c00 55 8bec 81c4a4feffff }
		$sequence_3 = { 894609 837f0414 7305 8b5704 }
		$sequence_4 = { 897dfc 8d9df6fdffff 53 ff7508 e8???????? 0bc0 }
		$sequence_5 = { 57 e8???????? 0bc0 0f848b000000 53 6804010000 }
		$sequence_6 = { 53 e8???????? 57 6806020000 56 }
		$sequence_7 = { 50 68???????? 68???????? 8d45e8 50 68???????? 6a05 }
		$sequence_8 = { 6a00 6a00 6809100000 ff7320 e8???????? 8945fc }
		$sequence_9 = { 0f85ce000000 68ea030000 ff7508 e8???????? 8bf8 }

	condition:
		7 of them and filesize <49152
}
