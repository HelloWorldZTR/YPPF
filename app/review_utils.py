from rest_framework import serializers
from rest_framework.pagination import PageNumberPagination
from django.core.exceptions import ValidationError as DjangoValidationError
from .models import CourseReview, ReviewCategories, NaturalPerson, ReviewReaction, Semester
from app.utils import get_classified_user
from datetime import datetime

class CourseReviewSerializer(serializers.ModelSerializer):
    """
    DRF Serializer for CourseReview model to handle form data from postReview.html
    """
    
    class Meta:
        model = CourseReview
        fields = [
            'course', 'teacher', 'title', 'text', 
            'rating_recommend', 'rating_content', 'rating_workload', 'rating_grade',
            'anonymous_flag', 'school_year', 'semester'
        ]
    
    # Override course field to validate against ReviewCategories
    course = serializers.PrimaryKeyRelatedField(
        queryset=ReviewCategories.objects.all(),
        error_messages={
            'required': '请选择课程',
            'does_not_exist': '所选课程不存在'
        }
    )
    
    teacher = serializers.CharField(
        max_length=48,
        required=False,
        allow_blank=True,
        help_text='授课教师姓名（可选）'
    )
    
    title = serializers.CharField(
        max_length=100,
        error_messages={
            'required': '请输入测评标题',
            'blank': '测评标题不能为空',
            'max_length': '测评标题不能超过100个字符'
        }
    )
    
    text = serializers.CharField(
        style={'base_template': 'textarea.html'},
        error_messages={
            'required': '请输入详细评价',
            'blank': '详细评价不能为空'
        }
    )
    
    school_year = serializers.IntegerField(
        error_messages={
            'required': '请选择学年',
            'invalid': '学年格式错误'
        }
    )
    
    semester = serializers.ChoiceField(
        choices=Semester.choices,
        error_messages={
            'required': '请选择学期',
            'invalid_choice': '学期选择无效'
        }
    )
    
    rating_recommend = serializers.ChoiceField(
        choices=CourseReview.Rating.choices,
        default=CourseReview.Rating.FIVE,
        error_messages={
            'invalid_choice': '总体评价必须在1-5之间'
        }
    )
    
    rating_content = serializers.ChoiceField(
        choices=CourseReview.Rating.choices,
        default=CourseReview.Rating.FIVE,
        error_messages={
            'invalid_choice': '内容质量评分必须在1-5之间'
        }
    )
    
    rating_workload = serializers.ChoiceField(
        choices=CourseReview.Rating.choices,
        default=CourseReview.Rating.FIVE,
        error_messages={
            'invalid_choice': '工作量评分必须在1-5之间'
        }
    )
    
    rating_grade = serializers.ChoiceField(
        choices=CourseReview.Rating.choices,
        default=CourseReview.Rating.FIVE,
        error_messages={
            'invalid_choice': '考核评分必须在1-5之间'
        }
    )
    
    anonymous_flag = serializers.BooleanField(
        default=False,
        required=False
    )
    
    def validate_title(self, value):
        """Validate title field"""
        if not value or not value.strip():
            raise serializers.ValidationError('测评标题不能为空')
        return value.strip()
    
    def validate_text(self, value):
        """Validate text field"""
        if not value or not value.strip():
            raise serializers.ValidationError('详细评价不能为空')
        if len(value.strip()) < 10:
            raise serializers.ValidationError('详细评价至少需要10个字符')
        return value.strip()
    
    def validate_rating_recommend(self, value):
        """Validate rating_recommend field"""
        try:
            rating_int = int(value)
            if rating_int not in [1, 2, 3, 4, 5]:
                raise serializers.ValidationError('评分必须在1-5之间')
            return rating_int
        except (ValueError, TypeError):
            raise serializers.ValidationError('评分格式错误')
    
    def validate_rating_content(self, value):
        """Validate rating_content field"""
        try:
            rating_int = int(value)
            if rating_int not in [1, 2, 3, 4, 5]:
                raise serializers.ValidationError('评分必须在1-5之间')
            return rating_int
        except (ValueError, TypeError):
            raise serializers.ValidationError('评分格式错误')
    
    def validate_rating_workload(self, value):
        """Validate rating_workload field"""
        try:
            rating_int = int(value)
            if rating_int not in [1, 2, 3, 4, 5]:
                raise serializers.ValidationError('评分必须在1-5之间')
            return rating_int
        except (ValueError, TypeError):
            raise serializers.ValidationError('评分格式错误')
    
    def validate_rating_grade(self, value):
        """Validate rating_grade field"""
        try:
            rating_int = int(value)
            if rating_int not in [1, 2, 3, 4, 5]:
                raise serializers.ValidationError('评分必须在1-5之间')
            return rating_int
        except (ValueError, TypeError):
            raise serializers.ValidationError('评分格式错误')
    
    def validate_school_year(self, value):
        """Validate school year"""
        current_year = datetime.now().year
        current_month = datetime.now().month
        
        # Determine current academic year (starts in September)
        if current_month >= 9:
            current_academic_year = current_year
        else:
            current_academic_year = current_year - 1
        
        # Check if year is too far in the past (more than 4 years)
        if value < current_academic_year - 4:
            raise serializers.ValidationError('不能选择超过4年前的学年')
        
        # Check if year is in the future
        if value > current_academic_year:
            raise serializers.ValidationError('不能选择未来的学年')
        
        return value
    
    def validate(self, data):
        """Cross-field validation for semester and year combination"""
        school_year = data.get('school_year')
        semester = data.get('semester')
        
        if school_year and semester:
            current_date = datetime.now()
            current_year = current_date.year
            current_month = current_date.month
            
            # Check if the selected semester is in the future
            is_future = False
            
            if school_year > current_year:
                is_future = True
            elif school_year == current_year:
                if semester == 'Fall' and current_month < 9:
                    is_future = True
                elif semester == 'Spring' and current_month < 2:
                    is_future = True
            elif school_year == current_year - 1:
                if semester == 'Fall' and current_month < 2:
                    # Fall semester of previous year is still valid if we're in Jan
                    pass
                elif semester == 'Spring' and current_month < 9:
                    # Spring semester of previous year is valid until September
                    pass
            
            if is_future:
                raise serializers.ValidationError('不能选择未来的学期')
        
        return data
    
    def create(self, validated_data):
        """
        Create a new CourseReview instance
        
        Args:
            validated_data (dict): Validated data from serializer
            
        Returns:
            CourseReview: The created review instance
        """
        # Extract reviewer from context
        request = self.context.get('request')
        if request and hasattr(request, 'user'):
            validated_data['reviewer'] = request.user
        
        return super().create(validated_data)

class ReviewCategoriesSerializer(serializers.ModelSerializer):
    """
    Serializer for ReviewCategories to provide course data for frontend
    """
    
    class Meta:
        model = ReviewCategories
        fields = ['id', 'course_name', 'course_type']
    
    def to_representation(self, instance):
        """
        Convert the model instance to a dictionary for frontend consumption
        """
        return {
            'id': instance.id,
            'name': instance.course_name,
            'category': instance.get_course_type_display()
        }

def get_course_data_for_frontend():
    """
    Get course data formatted for frontend consumption using DRF serializer
    
    Returns:
        list: List of dictionaries with course data
    """
    courses = ReviewCategories.objects.all().order_by('course_name')
    serializer = ReviewCategoriesSerializer(courses, many=True)
    return serializer.data

class CourseReviewListSerializer(serializers.ModelSerializer):
    reviewer = serializers.SerializerMethodField()
    reviewer_avatar = serializers.SerializerMethodField()
    semester = serializers.SerializerMethodField()
    time = serializers.SerializerMethodField()
    likes = serializers.SerializerMethodField()
    dislikes = serializers.SerializerMethodField()
    liked = serializers.SerializerMethodField()
    disliked = serializers.SerializerMethodField()

    class Meta:
        model = CourseReview
        fields = [
            'id',
            'reviewer','reviewer_avatar', 'title', 'text', 'rating_recommend', 
            'rating_content', 'rating_workload', 'rating_grade',
            'time', 'semester', 'teacher', 'likes', 'dislikes',
            'liked', 'disliked',
            'visibility'
        ]

    def get_reviewer(self, obj):
        return obj.reviewer.get_username() if not obj.anonymous_flag else "匿名用户"

    def get_reviewer_avatar(self, obj):
        try:
            classified_user = get_classified_user(obj.reviewer)
            return classified_user.get_user_ava() if not obj.anonymous_flag else NaturalPerson.get_user_ava()
        except AssertionError: # if not person or org
            return NaturalPerson.get_user_ava() # Use default avatar
        
    def get_semester(self, obj):
        semester_num = 1 if obj.semester == 'Spring' else 2
        return f"{obj.school_year}-{obj.school_year + 1}-{semester_num}"

    def get_time(self, obj):
        return obj.time.strftime("%Y-%m-%d")
    
    def get_likes(self, obj):
        return obj.reactions.filter(reaction=ReviewReaction.ReactionType.LIKE).count()

    def get_dislikes(self, obj):
        return obj.reactions.filter(reaction=ReviewReaction.ReactionType.DISLIKE).count()

    def get_liked(self, obj):
        request = self.context.get("request")
        if request and request.user.is_authenticated:
            return obj.reactions.filter(user=request.user, reaction=ReviewReaction.ReactionType.LIKE).exists()
        return False

    def get_disliked(self, obj):
        request = self.context.get("request")
        if request and request.user.is_authenticated:
            return obj.reactions.filter(user=request.user, reaction=ReviewReaction.ReactionType.DISLIKE).exists()
        return False

class CourseReviewPagination(PageNumberPagination):
    page_size = 5
    page_size_query_param = 'page_size'
    max_page_size = 20

class CourseRatingSerializer(serializers.Serializer):
    recommend = serializers.FloatField()
    content = serializers.FloatField()
    workload = serializers.FloatField()
    grade = serializers.FloatField()

class SemesterRatingSerializer(serializers.Serializer):
    name = serializers.CharField()
    recommend = serializers.FloatField()
    content = serializers.FloatField()
    workload = serializers.FloatField()
    grade = serializers.FloatField()

class CourseInfoSerializer(serializers.Serializer):
    overall = CourseRatingSerializer()
    semesters = SemesterRatingSerializer(many=True)
    total_pages = serializers.IntegerField()
