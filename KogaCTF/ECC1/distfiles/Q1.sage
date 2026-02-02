a, b = ???

E=EllipticCurve(QQbar, [a, b])
#楕円曲線E:y^2=x^3+a*x+b を作るときはEllipticCurve(QQbar, [a, b]) とする.
#問題文から，a,bを適宜置き換えること
#printすると，(x:y:z)のフォーマットに従って表示され，これは射影座標系を採用しているからです．
P=E(1,4)
print("P=",P)
#問題文に記されているQの値を代入
Q=???
print("Q=",Q)

x, y = (P-Q).xy()
print(f"CSL24{{{x}:{y}}}".replace("?", ""))