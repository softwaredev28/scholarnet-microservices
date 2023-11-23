package net.portofolio.studentmanagement.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;
import org.springframework.http.HttpStatus;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder(toBuilder = true)
public class CommonResponse<T>{

    private T data;
    private String errors;
    private String token;
    private String refreshToken;
    private HttpStatus statusCode;
    private String errorMessage;

    @JsonProperty("errorMessage")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public String getErrorMessage() {
        return errorMessage;
    }

    @JsonProperty("refreshToken")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public String getRefreshToken() {
        return refreshToken;
    }

    @JsonProperty("token")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public String getToken() {
        return token;
    }

    @JsonProperty("statusCode")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public HttpStatus getStatusCode() {
        return statusCode;
    }

    @JsonProperty("data")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public T getData() {
        return data;
    }

    @JsonProperty("errors")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public String getErrors() {
        return errors;
    }
}
