rule MALPEDIA_Win_Mulcom_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "8b428090-6e4d-587e-a305-32305b35e9f8"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mulcom"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.mulcom_auto.yar#L1-L132"
		license_url = "N/A"
		logic_hash = "0fb6c90115244992995c28d6d59f0334f00cc1075a3607803abc8b37e1b5b55f"
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
		$sequence_0 = { 4883ec40 33ff 48c740f007000000 488978e8 488d4c2420 668978d8 4d85c0 }
		$sequence_1 = { e8???????? 4c8b4310 488bd3 48837b1808 7203 488b13 4981f804010000 }
		$sequence_2 = { e8???????? 488d4de8 e8???????? 488d4dc8 e8???????? 488d4da8 e8???????? }
		$sequence_3 = { 48897020 488b05???????? 4833c4 48898510020000 498bf8 488bda 4889542438 }
		$sequence_4 = { 33d2 33c9 458bc6 ff15???????? 85c0 0f8412020000 }
		$sequence_5 = { e8???????? 488d4c2460 e8???????? 90 488dbea0000000 488d9580010000 }
		$sequence_6 = { 4c897de0 488d45d0 48837de810 480f4345d0 448838 8b542440 483b55e0 }
		$sequence_7 = { 4d63df 4c015d00 478d6c2fff eb3f 4585e4 7511 8b74243c }
		$sequence_8 = { cc e8???????? cc 4c8bc2 488b5108 48395110 0f848b000000 }
		$sequence_9 = { 410fb7d0 ff5018 440fb7c0 49ffce 418bff 66453be0 0f45fb }

	condition:
		7 of them and filesize <867328
}
