rule MALPEDIA_Win_Snatch_Loader_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "27465de5-7033-587f-a756-9377f064a810"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.snatch_loader"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.snatch_loader_auto.yar#L1-L176"
		license_url = "N/A"
		logic_hash = "0092d0e62ac35cefc4568a8a8fbdf579b918d859e448f714bc73aa915417d36e"
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
		$sequence_0 = { 66894606 a1???????? 85c0 7522 6a02 59 }
		$sequence_1 = { 8bc8 8b45fc 33d2 85c9 5e 0f45c2 8be5 }
		$sequence_2 = { 51 56 56 ffd0 8bc8 8b45fc 33d2 }
		$sequence_3 = { 33f6 8bd9 57 85c0 7522 6a02 }
		$sequence_4 = { ffd0 5f 85c0 7509 8bce e8???????? }
		$sequence_5 = { ffd0 85c0 8bce 0f457dfc }
		$sequence_6 = { 85c0 7505 8b45fc eb0d 53 53 }
		$sequence_7 = { 33f6 8bd6 8975fc 66397102 740b 42 }
		$sequence_8 = { 46 3bf3 76d8 33c0 48 5a 59 }
		$sequence_9 = { 741f 3a0439 7514 41 3b4df8 }
		$sequence_10 = { 68???????? 58 ffd0 8945f0 0bc0 }
		$sequence_11 = { 33d2 33c9 8a0431 0ac0 741f }
		$sequence_12 = { 52 ff750c e8???????? 8945fc 0bc0 7454 394508 }
		$sequence_13 = { 55 8bec 83c4fc 53 33db 837d0800 }
		$sequence_14 = { 3b45fc 773b 8b750c 8b7d10 037508 8bde }
		$sequence_15 = { 7206 3c5a 7702 0c20 c1c210 }

	condition:
		7 of them and filesize <262144
}
