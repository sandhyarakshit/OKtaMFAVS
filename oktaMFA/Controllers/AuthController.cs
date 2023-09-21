using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using oktaMFA.Models;
using oktaMFA.Service;
using System;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using static System.Net.WebRequestMethods;

namespace oktaMFA.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : Controller
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IOptions<OktaTokenSetting> _options;
       private readonly IMfaService _mfaService;
        public AuthController(IHttpClientFactory httpClientFactory, IOptions<OktaTokenSetting> options, IMfaService mfaservice)
        {
            _httpClientFactory = httpClientFactory;
            _options = options;
            _mfaService = mfaservice;
        }
        
        

        [HttpPost("authenticate-user")]
        public async Task<IActionResult> GetUserID([FromBody] OktaAuthnRequest request)
        {
            try
            {
                var httpClient = _httpClientFactory.CreateClient();
                var url = "https://dev-03848180.okta.com/api/v1/authn";

                var requestBody = JsonConvert.SerializeObject(new
                {
                    username = request.Username,
                    password = request.Password,
                    options = new
                    {
                        multiOptionalFactorEnroll = request.Options.MultiOptionalFactorEnroll,
                        warnBeforePasswordExpired = request.Options.WarnBeforePasswordExpired
                    }
                });

                var content = new StringContent(requestBody, Encoding.UTF8, "application/json");
                var response = await httpClient.PostAsync(url, content);

                if (response.IsSuccessStatusCode)
                {
                    var responseContent = await response.Content.ReadAsStringAsync();
                    var responseObject = JsonConvert.DeserializeObject<OktaAuthnResponse>(responseContent);
                    //FactorPayload payload = new FactorPayload();
                    //var getFactorid = await _mfaService.EnrollUser( responseObject.Embedded.user.id , payload);
                    //var getQr = getFactorid.Embedded.Activation.links.QRCode.Href;
                    //return Ok(new { Response = responseObject, QrUrl = getQr });
                    return Ok(responseObject);
                }
                else
                {

                    var errorResponseContent = await response.Content.ReadAsStringAsync();
                   var errorResponse = JsonConvert.DeserializeObject<ErrorResponse>(errorResponseContent);
                    return BadRequest($"Failed to verify factor. Error: {errorResponseContent}");
                }
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [HttpPost("enroll-user-factors")]
        public async Task<IActionResult> EnrollUserFactors(string userId, FactorPayload factorPayload)
        {

            try
            {
                //FactorPayload factorpayload;
                var enrolledUser = await _mfaService.EnrollUser(userId , factorPayload);
                if(enrolledUser != null)
                {

                    return Ok(enrolledUser);
                }
                else
                {
                    return BadRequest("User is already enrolled"); 
                }
               
            }
            catch (Exception ex)
            {
                return BadRequest($"An error occurred: {ex.Message}");
            }
        }


        [HttpPost("activate-otp")]
        public async Task<IActionResult> ActivateFactor([FromBody] PasscodeRequest passcodeRequest)

        {
           
            var  otp = await _mfaService.ActivateOtp(passcodeRequest);
            if(otp != null)
            {
                return Ok(otp);
            }
            return null;
        }


        //[HttpPost("activate")]
        //public async Task<IActionResult> ActivateFactor([FromBody] PasscodeRequest passcode)
        //{
        //    try
        //    {
        //        if (string.IsNullOrEmpty(passcode.factorId))
        //        {
        //            return BadRequest("Invalid factor ID provided.");
        //        }
        //        var domain = _options.Value.Domain;
        //        var apiKey = _options.Value.Api_key;
        //        var httpClient = _httpClientFactory.CreateClient();
        //        var userFactorsUrl = $"{domain}/api/v1/users/{passcode.userId}/factors/{passcode.factorId}/lifecycle/activate";

        //        var passcodePayload = new { passCode = passcode.passcode };
        //        var content = new StringContent(JsonConvert.SerializeObject(passcodePayload), Encoding.UTF8, "application/json");

        //        httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);

        //        var response = await httpClient.PostAsync(userFactorsUrl, content);

        //        if (response.IsSuccessStatusCode)
        //        {
        //            var responseContent = await response.Content.ReadAsStringAsync();
        //            var passcodeResponse = JsonConvert.DeserializeObject<ActivateResponse>(responseContent);
        //            return Ok(passcodeResponse);
        //        }
        //        else if (response.StatusCode == HttpStatusCode.BadRequest)
        //        {
        //            var errorResponseContent = await response.Content.ReadAsStringAsync();
        //            var errorResponse = JsonConvert.DeserializeObject<ErrorResponse>(errorResponseContent);

        //            if (errorResponse?.ErrorCode == "E0000001" && errorResponse.ErrorCauses.Any(cause => cause.ErrorSummary == "Factor is already active."))
        //            {
        //                return BadRequest("Factor is already active.");
        //            }
        //            else
        //            {
        //                return BadRequest($"Failed to activate user factor. Error: {errorResponseContent}");
        //            }
        //        }
        //        else
        //        {
        //            return BadRequest($"Failed to activate user factor. Status: {response.StatusCode}");
        //        }
        //    }
        //    catch (HttpRequestException ex)
        //    {

        //        return BadRequest($"Failed to activate user factor. Error: {ex.Message}");
        //    }
        //    catch (Exception ex)
        //    {
        //        // Log the exception for debugging purposes
        //        return BadRequest($"An error occurred: {ex.Message}");
        //    }
        //}
        [HttpPost("verify")]
        public async Task<IActionResult> VerifyFactor(string userId, string factorId, string passcode)
        {
            try
            {
                var verified = await _mfaService.VerifyOtp(userId, factorId, passcode);
                if (verified != null)
                {
                    return Ok(verified);
                }
                return null;

                //var apiKey = _options.Value.Api_key;
                //var oktaDomain = _options.Value.Domain;
                //var httpClient = _httpClientFactory.CreateClient();

                //var verifyFactorUrl = $"{oktaDomain}/api/v1/users/{userId}/factors/{factorId}/verify";

                //var verifyPayload = new { passCode = passcode };
                //var content = new StringContent(JsonConvert.SerializeObject(verifyPayload), Encoding.UTF8, "application/json");

                //httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("SSWS", apiKey);

                //var response = await httpClient.PostAsync(verifyFactorUrl, content);

                //if (response.IsSuccessStatusCode)
                //{
                //    var responseContent = await response.Content.ReadAsStringAsync();
                //    var verifyResponse = JsonConvert.DeserializeObject<FactorResponse>(responseContent);

                //    // Handle success as needed
                //    return Ok(verifyResponse);
                //}
                //else
                //{
                //    var errorResponseContent = await response.Content.ReadAsStringAsync();

                //    // Handle error response appropriately
                //    return BadRequest($"Failed to verify factor. Error: {errorResponseContent}");
                //}
            }
            catch (HttpRequestException ex)
            {
              
                return BadRequest($"Failed to verify factor. Error: {ex.Message}");
            }
            catch (Exception ex)
            {
                return BadRequest($"An error occurred: {ex.Message}");
            }
        }

       


    }
}

