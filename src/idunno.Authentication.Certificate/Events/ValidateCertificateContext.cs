﻿// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Security.Cryptography.X509Certificates;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace idunno.Authentication.Certificate
{
    public class ValidateCertificateContext : ResultContext<CertificateAuthenticationOptions>
    {
        /// <summary>
        /// Creates a new instance of <see cref="ValidateCertificateContext"/>.
        /// </summary>
        /// <param name="context">The HttpContext the validate context applies too.</param>
        /// <param name="scheme">The scheme used when the Basic Authentication handler was registered.</param>
        /// <param name="options">The <see cref="BasicAuthenticationOptions"/> for the instance of
        /// <see cref="BasicAuthenticationMiddleware"/> creating this instance.</param>
        /// <param name="ticket">Contains the intial values for the identit.</param>
        public ValidateCertificateContext(
            HttpContext context,
            AuthenticationScheme scheme,
            CertificateAuthenticationOptions options)
            : base(context, scheme, options)
        {
        }

        /// <summary>
        /// The certificate to validate.
        /// </summary>
        public X509Certificate2 ClientCertificate { get; set; }
    }
}
