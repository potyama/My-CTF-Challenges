# GeoGuessr4

|ジャンル|問題名|作問者|タグ|最終スコア|Solve数|
|---|---|---|---|---|---|
|Forensic/OSINT|GeoGuessr4|*anonymous*|Hard|133|217|
## Description(問題文)

この写真を撮っている人の座標を指定してください。
また、座標を直接指定すると誤差の許容範囲が表示されません。マウスクリックでご確認ください。

Please specify the coordinates of the person who took this photo.
Note that if you enter the coordinates directly, the tolerance zone will not be shown. Please check it by clicking with the mouse.

## Solution
The flag on the left is Denmark’s, but the license plate doesn’t look like it’s from the EU.
Also, you can faintly see a US flag in the distance on the right.

So I searched for “America Denmark town” and got Solvang, California.
Next, there’s a sign that looks like it says “cond st.”, but since 2nd St exists on Google Maps, I assumed it meant Second St.

After carefully checking the streets, you can find this spot:
https://www.google.com/maps/place/Solvang,+CA+93463,+USA/@34.5953112,-120.140825,3a,90y,279.43h,89.66t/data=!3m7!1e1!3m5!1sRblApJ--hUrxBvFFMa4qEw!2e0!6shttps:%2F%2Fstreetviewpixels-pa.googleapis.com%2Fv1%2Fthumbnail%3Fcb_client%3Dmaps_sv.tactile%26w%3D900%26h%3D600%26pitch%3D0.34343517044811733%26panoid%3DRblApJ--hUrxBvFFMa4qEw%26yaw%3D279.42647744513164!7i16384!8i8192!4m6!3m5!1s0x80e954a0fc922285:0x2d0e281b060bc156!8m2!3d34.5958201!4d-120.1376481!16zL20vMHI2NDA?entry=ttu&g_ep=EgoyMDI1MDgyNS4wIKXMDSoASAFQAw%3D%3D

This time, since you can see a crosswalk at the bottom of the image, you just need to place the pin there.

