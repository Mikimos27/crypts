#include <locale.h>
#include <gpgme.h>
#include <stdio.h>

void
init_gpgme (void)
{
    /* Initialize the locale environment.  */
    setlocale (LC_ALL, "");
    gpgme_check_version (NULL);
    gpgme_set_locale (NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
#ifdef LC_MESSAGES
    gpgme_set_locale (NULL, LC_MESSAGES, setlocale (LC_MESSAGES, NULL));
#endif
}


int main(){
    init_gpgme();
    printf("%s\n", gpgme_check_version(NULL));
    return 0;
}
