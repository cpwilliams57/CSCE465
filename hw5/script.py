h1 = "032772271db8f134e4914bca0e933361e1946c91c21e43610d301d39cbdb9d51"
h2 = "ec7ad191ba216d4afcbb1f2fcf83ae4d0d3abe4b51b9f09da49ee50d5feb3d28"

count = 0 

for x in range(len(h1)):
	if h1[x] == h2[x]: 
		count = count + 1

print count 