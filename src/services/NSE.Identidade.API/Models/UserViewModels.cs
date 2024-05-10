using System.ComponentModel.DataAnnotations;

namespace NSE.Identidade.API.Models
{
    public class UsuarioRegistro
    {
        [Required(ErrorMessage = "O Campo {0} é obrigatório")]
        [EmailAddress(ErrorMessage = "O Campo {0} inválido")]
        public string Email { get; set; }

        [Required(ErrorMessage = "O Campo {0} é obrigatório")]
        [StringLength(100, ErrorMessage = "O Campo {0} deve ter entre {2} e {1} caracteres", MinimumLength = 6)]
        public string Senha { get; set; }

        [Compare("Senha", ErrorMessage = "As senhas não conferem")]
        public string SenhaConfirmacao { get; set; }
    }

    public class UsuarioLogin
    {
        [Required(ErrorMessage = "O Campo {0} é obrigatório")]
        [EmailAddress(ErrorMessage = "O Campo {0} inválido")]
        public string Email { get; set; }

        [Required(ErrorMessage = "O Campo {0} é obrigatório")]
        [StringLength(100, ErrorMessage = "O Campo {0} deve ter entre {2} e {1} caracteres", MinimumLength = 6)]
        public string Senha { get; set; }

    }
}
