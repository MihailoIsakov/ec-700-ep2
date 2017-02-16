int main() {

    int a = 1, b = 1, c = 0;

    int n = 100;
    
    if (n == 0 || n == 1) {
        return 1;
    }

    for (int i = 2; i <= n; i++) {
        c = a + b;
        b = a;
        a = c;
    }

    return c;
}
