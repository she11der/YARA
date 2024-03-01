rule MALPEDIA_Win_Microbackdoor_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "32768709-e0c4-568e-99b5-4d92498e8c97"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.microbackdoor"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.microbackdoor_auto.yar#L1-L174"
		license_url = "N/A"
		logic_hash = "d87bae84a1434eb391a7ebc0d4af12aee586692c39928b7bf8d060b1c97f49c6"
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
		$sequence_0 = { 0fb74510 50 ff750c ff15???????? }
		$sequence_1 = { ffd7 eb06 ff15???????? 8bc6 eb06 }
		$sequence_2 = { 488bcd 418bdc 4d8bfc e8???????? 85db 755b 488d842478020000 }
		$sequence_3 = { 8939 488d4c2430 41b89c000000 e8???????? 488d4c2430 }
		$sequence_4 = { 74df 8d047506000000 50 6a40 ff15???????? 8bc8 894d0c }
		$sequence_5 = { 85c0 751d 837c247001 7516 395c2478 7610 488b4c2430 }
		$sequence_6 = { 4885db 7417 0fb7445ffe 6683f85c 7406 6683f82f }
		$sequence_7 = { 498bce 33f6 e8???????? 85ed }
		$sequence_8 = { 498bce 4489bc2488000000 453bc4 4c897c2420 }
		$sequence_9 = { 56 6a00 6a00 68???????? ff75f8 ff15???????? 85c0 }
		$sequence_10 = { ff15???????? 8d4336 50 6a40 ff15???????? 8bf8 }
		$sequence_11 = { 8bf8 897dd4 85ff 7498 837df800 b9???????? 8b5dfc }
		$sequence_12 = { ff15???????? 488bd8 4885c0 7512 ff15???????? 488d0d503e0000 }
		$sequence_13 = { 8bf8 e9???????? 33c0 40 e9???????? ff15???????? }
		$sequence_14 = { 83feff 743b 8b4d0c ff7510 894df4 ff15???????? 668945f2 }
		$sequence_15 = { 85c0 0f84bb010000 66833d????????00 0f84ad010000 }

	condition:
		7 of them and filesize <123904
}