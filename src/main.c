#include <stdio.h>
#include "app.h"

int main()
{
    App app = create_app();
    run_app(app);
    destroy_app(app);
    return 0;
}