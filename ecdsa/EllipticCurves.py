import numpy as np
import pylab as pl

Y, X = np.mgrid[-10:10:50j, -10:10:50j]

def f(x):
    return x**3 + 2*x + 4

pl.contour(X, Y, Y**2 - f(X), levels=[0])
pl.show()

#px = -1.0
#py = -np.sqrt(f(px))
##
#qx = 1
#qy = np.sqrt(f(qx))
##
#k = (qy - py)/(qx - px)
#b = -px*k + py 
##
#poly = np.poly1d([-1, k**2, 2*k*b+3, b**2-5])
##
#x = np.roots(poly)
#y = np.sqrt(f(x))
#
#pl.plot(x, y, "o")
#pl.plot(x, -y, "o")
#
##x = np.linspace(-5, 5)
##pl.plot(x, k*x+b)
#
#a=0:16  %all points of your finite field
#left_side = mod(a.^2,17)  %left side of the equation
#right_side = mod(a.^3+a+1,17) %right side of the equation
#
#points = [];
#
#
#%testing if left and right side are the same 
#%(you could probably do something nicer here)
#for i = 1:length(right_side)
#    I = find(left_side == right_side(i));
#    for j=1:length(I)
#        points = [points;a(i),a(I(j))];
#    end
#end
#
#plot(points(:,1),points(:,2),'ro')
#set(gca,'XTick',0:1:16)
#set(gca,'YTick',0:1:16)
#grid on;
